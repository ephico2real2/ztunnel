// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::{
    config::Config,
    identity::{PidClientTrait, WorkloadPid},
    inpod::WorkloadUid,
};
use cri::runtime_service_client::RuntimeServiceClient;
use hyper_util::rt::TokioIo;
use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};
use tokio::net::UnixStream;
use tonic::transport::Uri;
use tonic::{
    async_trait,
    transport::{Channel, Endpoint},
};
use tower::service_fn;
pub mod cri {
    tonic::include_proto!("runtime.v1");
}

pub struct ContainerRuntimeManager {
    runtime_client: RuntimeServiceClient<Channel>,
    timeout: Duration,
}
impl ContainerRuntimeManager {
    pub async fn new(cfg: &Config) -> Result<Self, std::io::Error> {
        if cfg.spire_timeout.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "positive SPIRE/CRI deadline required",
            ));
        }
        let channel = tokio::time::timeout(
            cfg.spire_timeout,
            Self::uds_channel(cfg.container_runtime_sock_path.clone()),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "node CRI connection deadline exceeded",
            )
        })?
        .map_err(|e| std::io::Error::other(format!("node CRI connection failed: {e}")))?;
        Ok(Self {
            runtime_client: RuntimeServiceClient::new(channel),
            timeout: cfg.spire_timeout,
        })
    }
    pub fn new_with_client(client: RuntimeServiceClient<Channel>) -> Self {
        Self {
            runtime_client: client,
            timeout: Duration::from_secs(10),
        }
    }
    async fn uds_channel(path: String) -> Result<Channel, tonic::transport::Error> {
        Endpoint::try_from("http://[::1]:50051")?.connect_with_connector(service_fn(move|_:Uri|{
            let path=path.clone();async move{Ok::<_,std::io::Error>(TokioIo::new(UnixStream::connect(path).await?))}
        })).await
    }
    pub async fn get_pids_for_pod(&self, pod_uid: String) -> Result<Vec<i32>, tonic::Status> {
        Ok(self
            .processes(&pod_uid)
            .await?
            .iter()
            .map(WorkloadPid::into_i32)
            .collect())
    }
    async fn processes(&self, pod_uid: &str) -> Result<Vec<WorkloadPid>, tonic::Status> {
        tokio::time::timeout(self.timeout, self.processes_inner(pod_uid))
            .await
            .map_err(|_| {
                tonic::Status::deadline_exceeded("node CRI workload observation deadline exceeded")
            })?
    }
    async fn processes_inner(&self, pod_uid: &str) -> Result<Vec<WorkloadPid>, tonic::Status> {
        let mut client = self.runtime_client.clone();
        let request = cri::ListPodSandboxRequest {
            filter: Some(cri::PodSandboxFilter {
                label_selector: HashMap::from([("io.kubernetes.pod.uid".into(), pod_uid.into())]),
                state: Some(cri::PodSandboxStateValue { state: 0 }),
                ..Default::default()
            }),
        };
        let sandboxes = client
            .list_pod_sandbox(request.clone())
            .await?
            .into_inner()
            .items;
        if sandboxes.is_empty() {
            return Err(tonic::Status::not_found(
                "No sandbox found for workload UID",
            ));
        }
        if sandboxes.len() != 1 {
            return Err(tonic::Status::failed_precondition(
                "ambiguous Ready sandboxes for workload UID",
            ));
        }
        let sandbox = &sandboxes[0];
        if sandbox.id.is_empty()
            || sandbox.state != 0
            || sandbox
                .labels
                .get("io.kubernetes.pod.uid")
                .map(String::as_str)
                != Some(pod_uid)
            || sandbox.metadata.as_ref().map(|m| m.uid.as_str()) != Some(pod_uid)
        {
            return Err(tonic::Status::failed_precondition(
                "CRI sandbox identity/state mismatch",
            ));
        }
        let mut containers = client
            .list_containers(cri::ListContainersRequest {
                filter: Some(cri::ContainerFilter {
                    pod_sandbox_id: sandbox.id.clone(),
                    state: Some(cri::ContainerStateValue { state: 1 }),
                    ..Default::default()
                }),
            })
            .await?
            .into_inner()
            .containers;
        if containers.is_empty() {
            return Err(tonic::Status::not_found(
                "No running containers found for workload UID",
            ));
        }
        if containers.len() > 256 {
            return Err(tonic::Status::resource_exhausted(
                "bounded container set exceeded",
            ));
        }
        // CRI list ordering is not stable; select deterministically and retain
        // exact sandbox/container IDs through the post-attestation rejoin.
        containers.sort_by(|a, b| a.id.cmp(&b.id));
        let mut ids = HashSet::new();
        let mut processes = Vec::new();
        let mut pids = HashSet::new();
        for container in containers {
            if container.id.is_empty()
                || !ids.insert(container.id.clone())
                || container.state != 1
                || container.pod_sandbox_id != sandbox.id
            {
                return Err(tonic::Status::failed_precondition(
                    "CRI container identity/state mismatch or duplicate",
                ));
            }
            let response = client
                .container_status(cri::ContainerStatusRequest {
                    container_id: container.id.clone(),
                    verbose: true,
                })
                .await?
                .into_inner();
            let status = response
                .status
                .as_ref()
                .ok_or_else(|| tonic::Status::failed_precondition("CRI container status absent"))?;
            if status.id != container.id || status.state != 1 || status.finished_at != 0 {
                return Err(tonic::Status::failed_precondition(
                    "CRI container status changed during observation",
                ));
            }
            #[derive(serde::Deserialize)]
            struct Info {
                pid: i32,
            }
            let info = response
                .info
                .get("info")
                .ok_or_else(|| tonic::Status::failed_precondition("CRI runtime PID info absent"))?;
            if info.len() > 1024 * 1024 {
                return Err(tonic::Status::resource_exhausted(
                    "bounded CRI PID info exceeded",
                ));
            }
            let info: Info = serde_json::from_str(info)
                .map_err(|_| tonic::Status::failed_precondition("invalid CRI runtime PID JSON"))?;
            if info.pid <= 0 || !pids.insert(info.pid) {
                return Err(tonic::Status::failed_precondition(
                    "invalid or duplicate running container PID",
                ));
            }
            processes.push(WorkloadPid::from_cri(
                info.pid,
                sandbox.id.clone(),
                container.id,
            ));
        }
        // Do not join container state to a retired/replaced sandbox snapshot.
        let again = client.list_pod_sandbox(request).await?.into_inner().items;
        if again != sandboxes {
            return Err(tonic::Status::failed_precondition(
                "CRI sandbox changed during observation",
            ));
        }
        Ok(processes)
    }
}
#[async_trait]
impl PidClientTrait for ContainerRuntimeManager {
    async fn fetch_pid(&self, uid: &WorkloadUid) -> Result<WorkloadPid, std::io::Error> {
        self.processes(&uid.clone().into_string())
            .await
            .map_err(|e| std::io::Error::other(format!("CRI error: {e}")))?
            .into_iter()
            .next()
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "No PID found for pod")
            })
    }
}

#[cfg(test)]
mod tests {
    use crate::{identity::PidClientTrait, inpod::WorkloadUid};
    use std::{collections::HashMap, sync::Arc};

    use http::Uri;
    use hyper_util::rt::TokioIo;
    use tokio::{
        net::{UnixListener, UnixStream},
        sync::Mutex,
    };
    use tokio_stream::wrappers::UnixListenerStream;
    use tonic::{
        Response,
        transport::{Endpoint, Server},
    };
    use tower::service_fn;

    use crate::container_runtime::{
        ContainerRuntimeManager,
        cri::{
            self, Container, ContainerStatusRequest, ContainerStatusResponse,
            ListContainersRequest, ListContainersResponse, PodSandbox, PodSandboxStatusRequest,
            PodSandboxStatusResponse, VersionRequest, VersionResponse,
            runtime_service_client::RuntimeServiceClient,
            runtime_service_server::{RuntimeService, RuntimeServiceServer},
        },
    };

    fn running_status(id: &str, pid: i32) -> cri::ContainerStatusResponse {
        cri::ContainerStatusResponse {
            status: Some(cri::ContainerStatus {
                id: id.into(),
                state: 1,
                ..Default::default()
            }),
            info: HashMap::from([("info".into(), format!("{{\"pid\":{pid}}}"))]),
        }
    }

    #[derive(Clone, Default)]
    struct MockRuntimeService {
        // You can put shared state here to control responses from your tests
        containers: Arc<Mutex<Vec<Container>>>,
        stall_sandbox: Arc<std::sync::atomic::AtomicBool>,
        sandboxes: Arc<Mutex<Vec<PodSandbox>>>,
        container_statuses: Arc<Mutex<HashMap<String, ContainerStatusResponse>>>,
    }

    #[tonic::async_trait]
    impl RuntimeService for MockRuntimeService {
        async fn version(
            &self,
            _request: tonic::Request<VersionRequest>,
        ) -> std::result::Result<tonic::Response<VersionResponse>, tonic::Status> {
            Ok(tonic::Response::new(VersionResponse::default()))
        }

        async fn pod_sandbox_status(
            &self,
            _request: tonic::Request<PodSandboxStatusRequest>,
        ) -> std::result::Result<tonic::Response<PodSandboxStatusResponse>, tonic::Status> {
            Ok(tonic::Response::new(PodSandboxStatusResponse::default()))
        }

        async fn list_pod_sandbox(
            &self,
            request: tonic::Request<cri::ListPodSandboxRequest>,
        ) -> std::result::Result<tonic::Response<cri::ListPodSandboxResponse>, tonic::Status>
        {
            if self.stall_sandbox.load(std::sync::atomic::Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            let sandboxes = self.sandboxes.lock().await.clone();
            let req = request.into_inner();

            let filtered = if let Some(filter) = req.filter {
                sandboxes
                    .into_iter()
                    .filter(|sandbox| {
                        // Filter by label selector
                        let labels_match =
                            filter.label_selector.iter().all(|(key, expected_value)| {
                                sandbox.labels.get(key) == Some(expected_value)
                            });
                        // Filter by state if specified
                        let state_match = filter
                            .state
                            .as_ref()
                            .is_none_or(|state_filter| sandbox.state == state_filter.state);
                        labels_match && state_match
                    })
                    .collect()
            } else {
                sandboxes
            };

            Ok(Response::new(cri::ListPodSandboxResponse {
                items: filtered,
            }))
        }

        async fn list_containers(
            &self,
            request: tonic::Request<ListContainersRequest>,
        ) -> std::result::Result<tonic::Response<ListContainersResponse>, tonic::Status> {
            let containers = self.containers.lock().await.clone();
            let req = request.into_inner();

            let filtered = if let Some(filter) = req.filter {
                containers
                    .into_iter()
                    .filter(|container| {
                        // Filter by sandbox ID if specified
                        let sandbox_match = if filter.pod_sandbox_id.is_empty() {
                            true
                        } else {
                            container.pod_sandbox_id == filter.pod_sandbox_id
                        };
                        // Filter by state if specified
                        let state_match = filter
                            .state
                            .as_ref()
                            .is_none_or(|state_filter| container.state == state_filter.state);
                        sandbox_match && state_match
                    })
                    .collect()
            } else {
                containers
            };

            Ok(Response::new(ListContainersResponse {
                containers: filtered,
            }))
        }

        async fn container_status(
            &self,
            request: tonic::Request<ContainerStatusRequest>,
        ) -> std::result::Result<tonic::Response<ContainerStatusResponse>, tonic::Status> {
            let container_status = self.container_statuses.lock().await;

            let container_id = request.into_inner().container_id.clone();

            let resp = container_status.get(&container_id).unwrap();

            Ok(tonic::Response::new(resp.clone()))
        }

        async fn status(
            &self,
            _request: tonic::Request<cri::StatusRequest>,
        ) -> std::result::Result<tonic::Response<cri::StatusResponse>, tonic::Status> {
            Ok(tonic::Response::new(cri::StatusResponse::default()))
        }
    }

    #[tokio::test]
    async fn test_client_uses_mock_cri_over_uds() {
        // 1. Prepare mock service and data
        let mock = MockRuntimeService::default();
        {
            let mut lock = mock.containers.lock().await;
            lock.push(Container {
                id: "fake-id-123".into(),
                pod_sandbox_id: "fake-sandbox-123".into(),
                state: 1, // CONTAINER_RUNNING
                ..Default::default()
            });

            let mut lock = mock.sandboxes.lock().await;
            lock.push(cri::PodSandbox {
                id: "fake-sandbox-123".into(),
                metadata: Some(cri::PodSandboxMetadata {
                    uid: "fake-uid-456".into(),
                    ..Default::default()
                }),
                labels: {
                    let mut m = HashMap::new();
                    m.insert("io.kubernetes.pod.uid".into(), "fake-uid-456".into());
                    m
                },
                ..Default::default()
            });

            let mut lock = mock.container_statuses.lock().await;
            lock.insert("fake-id-123".into(), running_status("fake-id-123", 4321));
            lock.insert("fake-id-321".into(), running_status("fake-id-321", 1234));
        }

        // 2. Create a temporary Unix socket path
        let socket_path = "/tmp/test-cri-runtime.sock";
        // Ensure old socket is gone if it exists
        let _ = std::fs::remove_file(socket_path);

        // 3. Bind UnixListener
        let uds = UnixListener::bind(socket_path).expect("failed to bind UDS");
        let incoming = UnixListenerStream::new(uds);

        // 4. Start gRPC server over UDS
        let svc = RuntimeServiceServer::new(mock.clone());
        let server_handle = tokio::spawn(async move {
            Server::builder()
                .add_service(svc)
                .serve_with_incoming(incoming)
                .await
                .expect("server failed");
        });

        // 5. Build a client Channel that dials the same UDS
        let socket_path_str = socket_path.to_string();
        let endpoint = Endpoint::try_from("http://[::]:50051").unwrap();
        let channel = endpoint
            .connect_with_connector(service_fn(move |_uri: Uri| {
                let path = socket_path_str.clone();
                async move {
                    let stream = UnixStream::connect(path).await?;
                    Ok::<_, std::io::Error>(TokioIo::new(stream))
                }
            }))
            .await
            .expect("failed to connect to mock UDS server");

        let client = RuntimeServiceClient::new(channel);

        // 6. Call the real client method against the mock server
        let cri_manager = ContainerRuntimeManager::new_with_client(client);
        let pids_result = cri_manager
            .get_pids_for_pod("non-existent-pod-uid".to_string())
            .await;
        assert!(pids_result.is_err()); // Since our mock returns no sandboxes matching the UID, this should error

        let pids_result = cri_manager
            .get_pids_for_pod("fake-uid-456".to_string())
            .await;
        assert!(pids_result.is_ok());
        assert_eq!(pids_result.unwrap(), vec![4321]);

        // 7. Clean up
        server_handle.abort();
        let _ = std::fs::remove_file(socket_path);
    }

    /// Helper to create a mock server and client for testing
    async fn setup_mock_server(
        mock: MockRuntimeService,
        socket_path: &str,
    ) -> (
        RuntimeServiceClient<tonic::transport::Channel>,
        tokio::task::JoinHandle<()>,
    ) {
        let _ = std::fs::remove_file(socket_path);
        let uds = UnixListener::bind(socket_path).expect("failed to bind UDS");
        let incoming = UnixListenerStream::new(uds);

        let svc = RuntimeServiceServer::new(mock);
        let server_handle = tokio::spawn(async move {
            Server::builder()
                .add_service(svc)
                .serve_with_incoming(incoming)
                .await
                .expect("server failed");
        });

        let socket_path_str = socket_path.to_string();
        let endpoint = Endpoint::try_from("http://[::]:50051").unwrap();
        let channel = endpoint
            .connect_with_connector(service_fn(move |_uri: Uri| {
                let path = socket_path_str.clone();
                async move {
                    let stream = UnixStream::connect(path).await?;
                    Ok::<_, std::io::Error>(TokioIo::new(stream))
                }
            }))
            .await
            .expect("failed to connect to mock UDS server");

        (RuntimeServiceClient::new(channel), server_handle)
    }

    #[tokio::test]
    async fn test_sandbox_not_ready_returns_not_found() {
        // Test that a sandbox in NotReady state (state=1) is filtered out
        let mock = MockRuntimeService::default();
        {
            let mut lock = mock.sandboxes.lock().await;
            lock.push(cri::PodSandbox {
                id: "not-ready-sandbox".into(),
                metadata: Some(cri::PodSandboxMetadata {
                    uid: "not-ready-pod-uid".into(),
                    ..Default::default()
                }),
                state: 1, // SANDBOX_NOTREADY
                labels: {
                    let mut m = HashMap::new();
                    m.insert("io.kubernetes.pod.uid".into(), "not-ready-pod-uid".into());
                    m
                },
                ..Default::default()
            });
        }

        let socket_path = "/tmp/test-cri-sandbox-not-ready.sock";
        let (client, server_handle) = setup_mock_server(mock, socket_path).await;

        let cri_manager = ContainerRuntimeManager::new_with_client(client);
        let result = cri_manager
            .get_pids_for_pod("not-ready-pod-uid".to_string())
            .await;

        // Should return not found because sandbox is not in Ready state
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);

        server_handle.abort();
        let _ = std::fs::remove_file(socket_path);
    }

    #[tokio::test]
    async fn test_exited_containers_filtered_out() {
        // Test that containers not in Running state are filtered out
        let mock = MockRuntimeService::default();
        {
            // Add a ready sandbox
            let mut lock = mock.sandboxes.lock().await;
            lock.push(cri::PodSandbox {
                id: "ready-sandbox-123".into(),
                metadata: Some(cri::PodSandboxMetadata {
                    uid: "pod-with-exited-containers".into(),
                    ..Default::default()
                }),
                state: 0, // SANDBOX_READY
                labels: {
                    let mut m = HashMap::new();
                    m.insert(
                        "io.kubernetes.pod.uid".into(),
                        "pod-with-exited-containers".into(),
                    );
                    m
                },
                ..Default::default()
            });

            // Add containers that are NOT running (exited)
            let mut lock = mock.containers.lock().await;
            lock.push(Container {
                id: "exited-container-1".into(),
                pod_sandbox_id: "ready-sandbox-123".into(),
                state: 2, // CONTAINER_EXITED
                ..Default::default()
            });
            lock.push(Container {
                id: "exited-container-2".into(),
                pod_sandbox_id: "ready-sandbox-123".into(),
                state: 0, // CONTAINER_CREATED
                ..Default::default()
            });

            // Add container statuses (should not be queried since containers are filtered)
            let mut lock = mock.container_statuses.lock().await;
            lock.insert(
                "exited-container-1".into(),
                running_status("exited-container-1", 0),
            );
        }

        let socket_path = "/tmp/test-cri-exited-containers.sock";
        let (client, server_handle) = setup_mock_server(mock, socket_path).await;

        let cri_manager = ContainerRuntimeManager::new_with_client(client);
        let result = cri_manager
            .get_pids_for_pod("pod-with-exited-containers".to_string())
            .await;

        // Should return NotFound error since no containers are running
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
        assert!(err.message().contains("No running containers found"));

        server_handle.abort();
        let _ = std::fs::remove_file(socket_path);
    }

    #[tokio::test]
    async fn test_mixed_container_states_returns_only_running() {
        // Test that only running containers are returned when there's a mix
        let mock = MockRuntimeService::default();
        {
            let mut lock = mock.sandboxes.lock().await;
            lock.push(cri::PodSandbox {
                id: "mixed-sandbox".into(),
                metadata: Some(cri::PodSandboxMetadata {
                    uid: "mixed-state-pod".into(),
                    ..Default::default()
                }),
                state: 0, // SANDBOX_READY
                labels: {
                    let mut m = HashMap::new();
                    m.insert("io.kubernetes.pod.uid".into(), "mixed-state-pod".into());
                    m
                },
                ..Default::default()
            });

            let mut lock = mock.containers.lock().await;
            // Running container
            lock.push(Container {
                id: "running-container".into(),
                pod_sandbox_id: "mixed-sandbox".into(),
                state: 1, // CONTAINER_RUNNING
                ..Default::default()
            });
            // Exited container
            lock.push(Container {
                id: "exited-container".into(),
                pod_sandbox_id: "mixed-sandbox".into(),
                state: 2, // CONTAINER_EXITED
                ..Default::default()
            });
            // Created but not started container
            lock.push(Container {
                id: "created-container".into(),
                pod_sandbox_id: "mixed-sandbox".into(),
                state: 0, // CONTAINER_CREATED
                ..Default::default()
            });

            let mut lock = mock.container_statuses.lock().await;
            lock.insert(
                "running-container".into(),
                running_status("running-container", 9999),
            );
            // Exited container would have PID 0
            lock.insert(
                "exited-container".into(),
                running_status("exited-container", 0),
            );
        }

        let socket_path = "/tmp/test-cri-mixed-states.sock";
        let (client, server_handle) = setup_mock_server(mock, socket_path).await;

        let cri_manager = ContainerRuntimeManager::new_with_client(client);
        let result = cri_manager
            .get_pids_for_pod("mixed-state-pod".to_string())
            .await;

        // Should only return the PID of the running container
        assert!(result.is_ok());
        let pids = result.unwrap();
        assert_eq!(pids, vec![9999]);

        server_handle.abort();
        let _ = std::fs::remove_file(socket_path);
    }
    fn bound_mock() -> MockRuntimeService {
        let mock = MockRuntimeService::default();
        // Tests call this only outside a poll of these mutexes.
        let uid = "11111111-2222-3333-4444-555555555555";
        mock.sandboxes.try_lock().unwrap().push(cri::PodSandbox {
            id: "sandbox-original".into(),
            state: 0,
            metadata: Some(cri::PodSandboxMetadata {
                uid: uid.into(),
                ..Default::default()
            }),
            labels: HashMap::from([("io.kubernetes.pod.uid".into(), uid.into())]),
            ..Default::default()
        });
        mock.containers.try_lock().unwrap().push(Container {
            id: "a".repeat(64),
            pod_sandbox_id: "sandbox-original".into(),
            state: 1,
            ..Default::default()
        });
        mock.container_statuses
            .try_lock()
            .unwrap()
            .insert("a".repeat(64), running_status(&"a".repeat(64), 123));
        mock
    }

    #[tokio::test]
    async fn native_cri_rejects_ambiguous_ready_sandboxes() {
        let mock = bound_mock();
        let mut second = mock.sandboxes.lock().await[0].clone();
        second.id = "sandbox-second".into();
        mock.sandboxes.lock().await.push(second);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runtime.sock");
        let (client, server) = setup_mock_server(mock, path.to_str().unwrap()).await;
        let error = ContainerRuntimeManager::new_with_client(client)
            .get_pids_for_pod("11111111-2222-3333-4444-555555555555".into())
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        assert!(error.message().contains("ambiguous"));
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn native_cri_checks_metadata_status_pid_and_duplicate_container() {
        for case in 0..6 {
            let mock = bound_mock();
            match case {
                0 => {
                    mock.sandboxes.lock().await[0]
                        .metadata
                        .as_mut()
                        .unwrap()
                        .uid = "wrong-uid".into()
                }
                1 => {
                    mock.container_statuses
                        .lock()
                        .await
                        .get_mut(&"a".repeat(64))
                        .unwrap()
                        .status = None
                }
                2 => {
                    mock.container_statuses
                        .lock()
                        .await
                        .get_mut(&"a".repeat(64))
                        .unwrap()
                        .status
                        .as_mut()
                        .unwrap()
                        .id = "wrong-container".into()
                }
                3 => {
                    mock.container_statuses
                        .lock()
                        .await
                        .get_mut(&"a".repeat(64))
                        .unwrap()
                        .status
                        .as_mut()
                        .unwrap()
                        .state = 2
                }
                4 => {
                    mock.container_statuses
                        .lock()
                        .await
                        .insert("a".repeat(64), running_status(&"a".repeat(64), 0));
                }
                5 => {
                    let duplicate = mock.containers.lock().await[0].clone();
                    mock.containers.lock().await.push(duplicate);
                }
                _ => unreachable!(),
            }
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("runtime.sock");
            let (client, server) = setup_mock_server(mock, path.to_str().unwrap()).await;
            let error = ContainerRuntimeManager::new_with_client(client)
                .get_pids_for_pod("11111111-2222-3333-4444-555555555555".into())
                .await
                .unwrap_err();
            assert_eq!(
                error.code(),
                tonic::Code::FailedPrecondition,
                "case {case}: {error}"
            );
            server.abort();
            let _ = server.await;
        }
    }

    #[tokio::test]
    async fn native_cri_reordered_containers_keep_same_exact_selection() {
        let mock = bound_mock();
        mock.containers.lock().await.insert(
            0,
            Container {
                id: "b".repeat(64),
                pod_sandbox_id: "sandbox-original".into(),
                state: 1,
                ..Default::default()
            },
        );
        mock.container_statuses
            .lock()
            .await
            .insert("b".repeat(64), running_status(&"b".repeat(64), 456));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runtime.sock");
        let (client, server) = setup_mock_server(mock.clone(), path.to_str().unwrap()).await;
        let manager = ContainerRuntimeManager::new_with_client(client);
        let uid = WorkloadUid::new("11111111-2222-3333-4444-555555555555".into());
        let first = manager.fetch_pid(&uid).await.unwrap();
        mock.containers.lock().await.reverse();
        let second = manager.fetch_pid(&uid).await.unwrap();
        assert_eq!(first, second);
        assert_eq!(first.container_id.as_deref(), Some("a".repeat(64).as_str()));
        assert_eq!(first.sandbox_id.as_deref(), Some("sandbox-original"));
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn native_cri_hung_sandbox_rpc_is_bounded() {
        let mock = bound_mock();
        mock.stall_sandbox
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runtime.sock");
        let (client, server) = setup_mock_server(mock, path.to_str().unwrap()).await;
        let mut manager = ContainerRuntimeManager::new_with_client(client);
        manager.timeout = std::time::Duration::from_millis(30);
        let start = std::time::Instant::now();
        let error = manager
            .get_pids_for_pod("11111111-2222-3333-4444-555555555555".into())
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::DeadlineExceeded);
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
        server.abort();
        let _ = server.await;
    }
}

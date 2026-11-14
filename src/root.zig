//! PocketRoot is a Zig-first portable security capability engine.
const std = @import("std");

pub const core = struct {
    pub const event_bus = @import("core/event_bus.zig");
    pub const artifact = @import("core/artifact.zig");
    pub const capability = @import("core/capability.zig");
    pub const network_observation = @import("core/network_observation.zig");
};

pub const device = struct {
    pub const command = @import("device/command.zig");
    pub const ipc = @import("device/ipc.zig");
};

pub const formats = struct {
    pub const dhcp = @import("formats/dhcp.zig");
    pub const dhcpv6 = @import("formats/dhcpv6.zig");
    pub const dns = @import("formats/dns.zig");
    pub const flipper_format = @import("formats/flipper_format.zig");
    pub const nbns = @import("formats/nbns.zig");
    pub const ssdp = @import("formats/ssdp.zig");
    pub const tls_certificate = @import("formats/tls_certificate.zig");
};

pub const services = struct {
    pub const storage = @import("services/storage.zig");
    pub const notification = @import("services/notification.zig");
    pub const archive = @import("services/archive.zig");
    pub const automation = @import("services/automation.zig");
    pub const workbench = @import("services/workbench.zig");
    pub const asset_graph = @import("services/asset_graph.zig");
    pub const vulnerability_matcher = @import("services/vulnerability_matcher.zig");
    pub const vulnerability_catalog = @import("services/vulnerability_catalog.zig");
    pub const project = @import("services/project.zig");
    pub const network_environment = @import("services/network_environment.zig");
    pub const network_discovery = @import("services/network_discovery.zig");
    pub const network_scan = @import("services/network_scan.zig");
    pub const neighbor_probe = @import("services/neighbor_probe.zig");
    pub const live_capture = @import("services/live_capture.zig");
    pub const library = @import("services/library.zig");
    pub const http_inspect = @import("services/http_inspect.zig");
    pub const tls_inspect = @import("services/tls_inspect.zig");
    pub const tcp_scan = @import("services/tcp_scan.zig");
    pub const workflow = @import("services/workflow.zig");
    pub const script = @import("services/script.zig");
    pub const script_builder = @import("services/script_builder.zig");
};

pub const protocols = struct {
    pub const protocol = @import("protocols/protocol.zig");
    pub const registry = @import("protocols/registry.zig");
    pub const badusb = @import("protocols/badusb.zig");
    pub const infrared = @import("protocols/infrared.zig");
    pub const lfrfid = @import("protocols/lfrfid.zig");
    pub const nfc = @import("protocols/nfc.zig");
    pub const ibutton = @import("protocols/ibutton.zig");
    pub const nmap = @import("protocols/nmap.zig");
    pub const nuclei = @import("protocols/nuclei.zig");
    pub const pcap = @import("protocols/pcap.zig");
    pub const subghz = @import("protocols/subghz.zig");
    pub const firmware = @import("protocols/firmware.zig");
};

pub const apps = struct {
    pub const app = @import("apps/app.zig");
    pub const infrared = @import("apps/infrared.zig");

    const builtins = [_]app.AppDescriptor{.{
        .id = "infrared",
        .name = "Infrared",
        .category = "Protocols",
        .entry = infrared.run,
    }};

    pub fn builtinApps() []const app.AppDescriptor {
        return &builtins;
    }
};

pub const simulator = struct {
    pub const device = @import("simulator/device.zig");
    pub const loopback = @import("simulator/loopback.zig");
    pub const Runtime = @import("simulator/runtime.zig").Runtime;
};

pub const EventBus = core.event_bus.EventBus;
pub const Event = core.event_bus.Event;
pub const Artifact = core.artifact.Artifact;
pub const ArtifactSource = core.artifact.ArtifactSource;
pub const CapabilityService = core.capability.Service;
pub const CapabilityRequest = core.capability.Request;
pub const CapabilityResult = core.capability.Result;
pub const AppContext = apps.app.AppContext;
pub const AppDescriptor = apps.app.AppDescriptor;
pub const AppManager = apps.app.AppManager;
pub const ProtocolDescriptor = protocols.protocol.ProtocolDescriptor;
pub const AnalysisResult = protocols.protocol.AnalysisResult;
pub const AnalysisField = protocols.protocol.AnalysisField;
pub const Finding = protocols.protocol.Finding;
pub const FindingSeverity = protocols.protocol.FindingSeverity;
pub const NetworkObservation = core.network_observation.NetworkObservation;
pub const NetworkObservationSpec = core.network_observation.Spec;
pub const NetworkObservationKind = core.network_observation.Kind;
pub const ObservationConfidence = core.network_observation.Confidence;
pub const ProtocolRegistry = protocols.registry.ProtocolRegistry;
pub const ProtocolWorkbench = services.workbench.ProtocolWorkbench;
pub const StorageService = services.storage.StorageService;
pub const NotificationService = services.notification.NotificationService;
pub const ArchiveService = services.archive.ArchiveService;
pub const AssetGraph = services.asset_graph.AssetGraph;
pub const Project = services.project.Project;
pub const inspectNetworkEnvironment = services.network_environment.inspect;
pub const discoverNetwork = services.network_discovery.discover;
pub const scanNetwork = services.network_scan.scan;
pub const probeNeighbors = services.neighbor_probe.probe;
pub const captureNetwork = services.live_capture.capture;
pub const inspectHttp = services.http_inspect.inspect;
pub const inspectTls = services.tls_inspect.inspect;
pub const scanTcp = services.tcp_scan.scan;
pub const WorkflowRunner = services.workflow.Runner;
pub const WorkflowDefinition = services.workflow.Definition;
pub const Script = services.script.Script;
pub const ScriptExecutor = services.script_builder.Executor;
pub const ScriptError = services.script.Error;

test {
    // Group structs (core/device/formats/...) do not force analysis of their nested
    // file containers, so their test blocks were silently skipped. Reference every
    // module container explicitly: this is also the canonical module list.
    std.testing.refAllDecls(@This());
    inline for (.{
        core.event_bus,
        core.artifact,
        core.capability,
        core.network_observation,
        device.command,
        device.ipc,
        formats.dhcp,
        formats.dhcpv6,
        formats.dns,
        formats.flipper_format,
        formats.nbns,
        formats.ssdp,
        formats.tls_certificate,
        protocols.protocol,
        protocols.registry,
        protocols.badusb,
        protocols.infrared,
        protocols.lfrfid,
        protocols.nfc,
        protocols.ibutton,
        protocols.nmap,
        protocols.nuclei,
        protocols.pcap,
        protocols.subghz,
        protocols.firmware,
        services.storage,
        services.notification,
        services.archive,
        services.automation,
        services.workbench,
        services.asset_graph,
        services.vulnerability_matcher,
        services.vulnerability_catalog,
        services.project,
        services.network_environment,
        services.network_discovery,
        services.network_scan,
        services.neighbor_probe,
        services.live_capture,
        services.library,
        services.http_inspect,
        services.tls_inspect,
        services.tcp_scan,
        services.workflow,
        services.script,
        services.script_builder,
        apps.app,
        apps.infrared,
        simulator.device,
        simulator.loopback,
    }) |module| {
        std.testing.refAllDecls(module);
    }
    _ = @import("fuzz_tests.zig");
}

// Hermes Hands, desktop half: the Hands pane and the status bar chip.
// Devices and relay state come from this plugin's /ui/state route (dashboard/plugin_api.py). The
// conversation's target, the target switch and pairing go through the owner-gated /hands command
// (hands/commands.py) over the gateway's slash.exec RPC, bound to the focused session.
import {
  atom,
  Button,
  CopyButton,
  host,
  Input,
  PANES_AREA,
  queryClient,
  relativeTime,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  STATUSBAR_AREAS,
  StatusDot,
  useQuery,
  useValue,
} from "@hermes/plugin-sdk";
import { useState } from "react";
import { jsx, jsxs } from "react/jsx-runtime";

const ID = "hermes-hands";
const PANE_ID = `${ID}:hands`;
const STATE_KEY = [ID, "ui-state"];
const TARGET_KEY = [ID, "target"];
const PANE_POLL_MS = 2000;
const CHIP_POLL_MS = 10000;
const SERVER = "server";

// The /hands status line, which alert lines may follow: "Hands: relay up; target laptop; 2 device(s)."
const STATUS_TARGET =
  /^Hands: relay (?:up|down); target (.+?); \d+ device\(s\)\.$/m;
const PAIR_CODE = /^Pair code: (.+)$/m;
const PAIR_COMMAND = /^Run on the device: (.+)$/m;

const styles = {
  pane: {
    display: "flex",
    flexDirection: "column",
    gap: 14,
    height: "100%",
    overflowY: "auto",
    padding: 12,
    fontSize: 12,
    color: "var(--ui-text-secondary)",
  },
  section: { display: "flex", flexDirection: "column", gap: 6 },
  label: { fontSize: 11, fontWeight: 600, color: "var(--ui-text-tertiary)" },
  row: { display: "flex", alignItems: "center", gap: 6 },
  device: {
    display: "flex",
    flexDirection: "column",
    gap: 2,
    paddingTop: 6,
    borderTop: "1px solid var(--ui-stroke-tertiary)",
  },
  name: { color: "var(--ui-text-primary)", fontWeight: 500 },
  quiet: { color: "var(--ui-text-tertiary)" },
  alert: { color: "var(--ui-red)" },
  code: {
    padding: 6,
    borderRadius: 3,
    background: "var(--ui-bg-quaternary)",
    color: "var(--ui-text-primary)",
    fontFamily: "ui-monospace, monospace",
    wordBreak: "break-all",
    userSelect: "text",
  },
  chip: { color: "var(--ui-text-tertiary)" },
};

function shellQuote(value) {
  return "'" + value.split("'").join("'\"'\"'") + "'";
}

function errorText(error) {
  return error instanceof Error ? error.message : String(error);
}

async function runHands(sessionId, args) {
  const result = await host.request("slash.exec", {
    session_id: sessionId,
    command: args ? `/hands ${args}` : "/hands",
  });
  return String(result?.output ?? "");
}

function useHandsState(ctx, refetchInterval) {
  return useQuery({
    queryKey: STATE_KEY,
    queryFn: () => ctx.rest("/ui/state"),
    refetchInterval,
  });
}

function useTarget(sessionId, refetchInterval) {
  return useQuery({
    queryKey: [...TARGET_KEY, sessionId],
    queryFn: async () =>
      STATUS_TARGET.exec(await runHands(sessionId, ""))?.[1] ?? null,
    enabled: Boolean(sessionId),
    refetchInterval,
  });
}

function relayDown(state) {
  return state.isError || state.data?.relay === false;
}

function RelayLine({ state }) {
  if (state.isPending) {
    return jsx("div", { style: styles.quiet, children: "Checking the relay…" });
  }
  const down = relayDown(state);
  const detail = state.isError ? errorText(state.error) : state.data.detail;
  return jsxs("div", {
    style: styles.section,
    children: [
      jsxs("div", {
        style: styles.row,
        children: [
          jsx(StatusDot, { tone: down ? "bad" : "good" }),
          jsx("span", {
            style: styles.name,
            children: down ? "Relay down" : "Relay up",
          }),
        ],
      }),
      down && detail
        ? jsx("div", { style: styles.quiet, children: detail })
        : null,
    ],
  });
}

function TargetPicker({ sessionId, target, devices }) {
  if (!sessionId) {
    return jsx("div", {
      style: styles.quiet,
      children: "Open a conversation to choose where its commands run.",
    });
  }
  const names = [SERVER, ...devices.map((device) => device.name)];
  if (target && !names.includes(target)) {
    names.push(target);
  }
  const choose = async (name) => {
    try {
      host.notify({
        kind: "info",
        message: await runHands(sessionId, `use ${shellQuote(name)}`),
      });
    } catch (error) {
      host.notifyError(error, "Hands could not switch the target.");
    }
    queryClient.invalidateQueries({ queryKey: TARGET_KEY });
  };
  return jsxs("div", {
    style: styles.section,
    children: [
      jsx("div", {
        style: styles.label,
        children: "This conversation runs on",
      }),
      jsxs(Select, {
        value: target ?? "",
        onValueChange: choose,
        children: [
          jsx(SelectTrigger, {
            style: { width: "100%" },
            children: jsx(SelectValue, { placeholder: "unknown" }),
          }),
          jsx(SelectContent, {
            children: names.map((name) =>
              jsx(SelectItem, { value: name, children: name }, name),
            ),
          }),
        ],
      }),
    ],
  });
}

function DeviceRow({ device }) {
  const tone = !device.policy_ok ? "bad" : device.online ? "good" : "muted";
  return jsxs("div", {
    style: styles.device,
    children: [
      jsxs("div", {
        style: styles.row,
        children: [
          jsx(StatusDot, { tone }),
          jsx("span", { style: styles.name, children: device.name }),
          jsx("span", {
            style: styles.quiet,
            children: device.online ? "online" : "offline",
          }),
        ],
      }),
      jsx("div", { style: styles.quiet, children: device.os }),
      jsx("div", {
        style: styles.quiet,
        children: `last seen ${relativeTime(device.last_seen * 1000)}`,
      }),
      jsx("div", {
        style: device.policy_ok ? styles.quiet : styles.alert,
        children: device.policy_ok
          ? "deny-list as paired"
          : "deny-list changed; the relay refuses this device",
      }),
    ],
  });
}

function DeviceList({ devices, alerts }) {
  return jsxs("div", {
    style: styles.section,
    children: [
      jsx("div", { style: styles.label, children: "Paired devices" }),
      devices.length === 0
        ? jsx("div", { style: styles.quiet, children: "No paired devices." })
        : devices.map((device) => jsx(DeviceRow, { device }, device.device_id)),
      alerts.map((alert) =>
        jsx("div", { style: styles.alert, children: alert }, alert),
      ),
    ],
  });
}

function PairResult({ reply }) {
  const code = PAIR_CODE.exec(reply)?.[1];
  const command = PAIR_COMMAND.exec(reply)?.[1];
  if (!code || !command) {
    return jsx("div", { style: styles.quiet, children: reply });
  }
  return jsxs("div", {
    style: styles.section,
    children: [
      jsx("div", {
        style: styles.quiet,
        children: "Pairing code (single use, expires in 10 minutes)",
      }),
      jsx("div", { style: styles.code, children: code }),
      jsx("div", { style: styles.quiet, children: "Run this on the device" }),
      jsx("div", { style: styles.code, children: command }),
      jsx(CopyButton, {
        text: command,
        label: "Copy command",
        showLabel: true,
      }),
    ],
  });
}

function PairForm({ sessionId }) {
  const [name, setName] = useState("");
  const [reply, setReply] = useState("");
  const [busy, setBusy] = useState(false);
  const pair = async () => {
    setBusy(true);
    try {
      setReply(await runHands(sessionId, `pair ${shellQuote(name.trim())}`));
    } catch (error) {
      setReply(errorText(error));
    } finally {
      setBusy(false);
    }
  };
  return jsxs("div", {
    style: styles.section,
    children: [
      jsx("div", { style: styles.label, children: "Pair a device" }),
      jsxs("div", {
        style: styles.row,
        children: [
          jsx(Input, {
            value: name,
            placeholder: "device name",
            disabled: !sessionId,
            onChange: (event) => setName(event.target.value),
          }),
          jsx(Button, {
            size: "sm",
            disabled: !sessionId || !name.trim() || busy,
            onClick: pair,
            children: "Pair",
          }),
        ],
      }),
      reply ? jsx(PairResult, { reply }) : null,
    ],
  });
}

function HandsPane({ ctx, $visible }) {
  const visible = useValue($visible);
  const sessionId = useValue(host.state.focusedSessionId);
  const interval = visible ? PANE_POLL_MS : false;
  const state = useHandsState(ctx, interval);
  const target = useTarget(sessionId, interval);
  const devices = state.data?.devices ?? [];
  return jsxs("div", {
    style: styles.pane,
    children: [
      jsx(RelayLine, { state }),
      jsx(TargetPicker, { sessionId, target: target.data ?? null, devices }),
      jsx(DeviceList, { devices, alerts: state.data?.alerts ?? [] }),
      jsx(PairForm, { sessionId }),
    ],
  });
}

function HandsChip({ ctx }) {
  const sessionId = useValue(host.state.focusedSessionId);
  const state = useHandsState(ctx, CHIP_POLL_MS);
  const target = useTarget(sessionId, CHIP_POLL_MS);
  const label = target.data ? `hands: ${target.data}` : "hands";
  return jsx(Button, {
    variant: "ghost",
    size: "xs",
    style: styles.chip,
    title: "Show the Hands pane",
    onClick: () => host.revealPane?.(PANE_ID),
    children: relayDown(state) ? `${label} | relay down` : label,
  });
}

export default {
  id: ID,
  name: "Hermes Hands",
  register(ctx) {
    // host.paneVisibility is missing on older desktops; there the pane polls whenever it is mounted.
    const $visible =
      typeof host.paneVisibility === "function"
        ? host.paneVisibility(PANE_ID)
        : atom(true);
    ctx.register({
      id: "hands",
      area: PANES_AREA,
      title: "Hands",
      data: { placement: "right", width: "300px" },
      render: () => jsx(HandsPane, { ctx, $visible }),
    });
    ctx.register({
      id: "chip",
      area: STATUSBAR_AREAS.right,
      order: 130,
      render: () => jsx(HandsChip, { ctx }),
    });
    ctx.onEvent(`plugin.${ID}.devices.changed`, () =>
      queryClient.invalidateQueries({ queryKey: STATE_KEY }),
    );
  },
};

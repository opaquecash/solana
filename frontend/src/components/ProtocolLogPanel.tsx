import { useState } from "react";
import { useProtocolLog } from "../context/ProtocolLogContext";
import type { ProtocolLogSource } from "../context/ProtocolLogContext";

const sourceLabel: Record<ProtocolLogSource, string> = {
  wasm: "WASM",
  blockchain: "CHAIN",
  ui: "UI",
};

const sourceClass: Record<ProtocolLogSource, string> = {
  wasm: "text-neutral-400",
  blockchain: "text-success",
  ui: "text-neutral-500",
};

export function ProtocolLogPanel() {
  const { entries, clear } = useProtocolLog();
  const [collapsed, setCollapsed] = useState(true);

  return (
    <div className="flex flex-col flex-1 min-h-0 bg-black">
      <button
        type="button"
        onClick={() => setCollapsed((c) => !c)}
        className="w-full shrink-0 flex items-center justify-between px-4 sm:px-6 py-2 text-left text-sm font-mono text-neutral-600 hover:text-neutral-400 transition-colors"
      >
        <span>
          Log {entries.length > 0 && `(${entries.length})`}
        </span>
        <span>{collapsed ? "+" : "−"}</span>
      </button>
      {!collapsed && (
        <div className="flex-1 min-h-0 overflow-y-auto px-4 sm:px-6 pb-4">
          <div className="flex justify-end mb-2">
            <button
              type="button"
              onClick={clear}
              className="text-xs font-mono text-neutral-600 hover:text-neutral-400 px-2 py-1 rounded-md border border-border hover:border-neutral-700 transition-colors"
            >
              Clear
            </button>
          </div>
          <ul className="space-y-1 font-mono text-xs">
            {entries.length === 0 ? (
              <li className="text-neutral-700">No entries yet.</li>
            ) : (
              entries.map((e) => (
                <li
                  key={e.id}
                  className="flex gap-2 items-baseline text-neutral-500"
                >
                  <span className={`shrink-0 w-12 ${sourceClass[e.source]}`}>
                    [{sourceLabel[e.source]}]
                  </span>
                  <span className="text-neutral-700 text-[10px] shrink-0">
                    {new Date(e.timestamp).toLocaleTimeString()}
                  </span>
                  <span className="break-all">{e.message}</span>
                </li>
              ))
            )}
          </ul>
        </div>
      )}
    </div>
  );
}

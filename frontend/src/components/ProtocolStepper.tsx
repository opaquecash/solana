import { useEffect, useRef } from "react";

export type StepStatus = "wait" | "ok" | "done" | "error";

export type ProtocolStep = {
  id: string;
  status: StepStatus;
  label: string;
  detail?: string;
};

type ProtocolStepperProps = {
  steps: ProtocolStep[];
  className?: string;
};

const statusConfig: Record<
  StepStatus,
  { badge: string; className: string }
> = {
  wait: {
    badge: "WAIT",
    className: "text-warning border-warning/20 bg-warning/5",
  },
  ok: {
    badge: "OK",
    className: "text-success border-success/20 bg-success/5",
  },
  done: {
    badge: "DONE",
    className: "text-white border-neutral-700 bg-neutral-800",
  },
  error: {
    badge: "ERR",
    className: "text-error border-error/20 bg-error/5",
  },
};

export function ProtocolStepper({ steps, className = "" }: ProtocolStepperProps) {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [steps]);

  return (
    <div
      ref={scrollRef}
      className={
        "max-h-64 overflow-y-auto rounded-lg border border-border bg-neutral-950 p-3 font-mono text-sm " +
        className
      }
    >
      {steps.length === 0 ? (
        <p className="text-neutral-600 text-xs">Waiting for protocol events…</p>
      ) : (
        <ul className="space-y-2">
          {steps.map((step) => {
            const config = statusConfig[step.status];
            return (
              <li key={step.id} className="flex flex-col gap-0.5">
                <div className="flex items-center gap-2 flex-wrap">
                  <span
                    className={
                      "inline-flex shrink-0 items-center px-1.5 py-0.5 rounded border text-xs font-medium " +
                      config.className
                    }
                  >
                    {config.badge}
                  </span>
                  <span className="text-neutral-300 text-xs">{step.label}</span>
                </div>
                {step.detail && (
                  <div className="pl-4 text-neutral-600 text-xs break-all">
                    {step.detail}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

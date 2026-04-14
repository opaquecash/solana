import {
  createContext,
  useCallback,
  useContext,
  useState,
  type ReactNode,
} from "react";

export type ToastExplorerTx = { cluster?: string; txSig: string };

type Toast = {
  id: string;
  message: string;
  explorerTx?: ToastExplorerTx;
};

type ToastContextValue = {
  toasts: Toast[];
  showToast: (message: string, options?: { explorerTx?: ToastExplorerTx }) => void;
  dismiss: (id: string) => void;
};

const ToastContext = createContext<ToastContextValue | null>(null);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const showToast = useCallback((message: string, options?: { explorerTx?: ToastExplorerTx }) => {
    const id = `toast-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
    setToasts((prev) => [...prev, { id, message, explorerTx: options?.explorerTx }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 5000);
  }, []);

  const dismiss = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={{ toasts, showToast, dismiss }}>
      {children}
    </ToastContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) return { toasts: [], showToast: () => {}, dismiss: () => {} };
  return ctx;
}

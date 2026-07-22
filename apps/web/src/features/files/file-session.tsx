import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

import { closeFileSession } from "../../shared/api/client";
import type { FileListView, FileSessionView } from "../../shared/api/types";

interface FileSessionController {
  session: FileSessionView | null;
  listing: FileListView | null;
  adopt: (session: FileSessionView) => void;
  rememberListing: (listing: FileListView) => void;
  discard: () => void;
  disconnect: () => Promise<boolean>;
}

const FileSessionContext = createContext<FileSessionController | null>(null);

export function FileSessionProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<FileSessionView | null>(null);
  const [listing, setListing] = useState<FileListView | null>(null);
  const sessionRef = useRef<FileSessionView | null>(null);

  useEffect(() => {
    sessionRef.current = session;
  }, [session]);

  const adopt = useCallback((next: FileSessionView): void => {
    sessionRef.current = next;
    setSession(next);
    setListing(null);
  }, []);

  const rememberListing = useCallback((next: FileListView): void => setListing(next), []);

  const discard = useCallback((): void => {
    sessionRef.current = null;
    setSession(null);
    setListing(null);
  }, []);

  const disconnect = useCallback(async (): Promise<boolean> => {
    const active = sessionRef.current;
    discard();
    if (active === null) return true;
    try {
      await closeFileSession(active.sessionToken);
      return true;
    } catch {
      return false;
    }
  }, [discard]);

  useEffect(() => {
    return () => {
      const active = sessionRef.current;
      if (active !== null) void closeFileSession(active.sessionToken).catch(() => undefined);
    };
  }, []);

  const value = useMemo<FileSessionController>(() => ({
    session,
    listing,
    adopt,
    rememberListing,
    discard,
    disconnect,
  }), [adopt, discard, disconnect, listing, rememberListing, session]);

  return <FileSessionContext.Provider value={value}>{children}</FileSessionContext.Provider>;
}

export function useFileSession(): FileSessionController {
  const controller = useContext(FileSessionContext);
  if (controller === null) throw new Error("FileSessionProvider is required");
  return controller;
}

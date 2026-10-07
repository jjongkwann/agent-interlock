"use client";

import { createContext, useCallback, useContext, useEffect, useSyncExternalStore, type ReactNode } from "react";
import { LANGUAGE_STORAGE_KEY, resolveLanguage, translate, type Language, type Message } from "./i18n";

let sessionLanguage: Language | null = null;
const languageEvent = "interlock-language-change";

function currentLanguage(): Language {
  if (sessionLanguage) return sessionLanguage;
  try { return resolveLanguage(localStorage.getItem(LANGUAGE_STORAGE_KEY), navigator.language); }
  catch { return resolveLanguage(null, navigator.language); }
}

function subscribe(listener: () => void) {
  const storageChanged = (event: StorageEvent) => {
    if (event.key === LANGUAGE_STORAGE_KEY || event.key === null) { sessionLanguage = null; listener(); }
  };
  window.addEventListener(languageEvent, listener);
  window.addEventListener("storage", storageChanged);
  return () => {
    window.removeEventListener(languageEvent, listener);
    window.removeEventListener("storage", storageChanged);
  };
}

function setLanguage(language: Language) {
  sessionLanguage = language;
  try { localStorage.setItem(LANGUAGE_STORAGE_KEY, language); } catch { /* Keep the selection for this session when storage is blocked. */ }
  window.dispatchEvent(new Event(languageEvent));
}

const LanguageContext = createContext<Language>("en");

export function LanguageProvider({ children, initialLanguage = "en" }: { children: ReactNode; initialLanguage?: Language }) {
  const language = useSyncExternalStore(subscribe, currentLanguage, () => initialLanguage);
  useEffect(() => {
    document.documentElement.lang = language;
    document.title = `Agent Interlock · ${translate(language, "Security Architecture Studio")}`;
  }, [language]);
  return <LanguageContext.Provider value={language}>{children}</LanguageContext.Provider>;
}

export function useLanguage() {
  const language = useContext(LanguageContext);
  const t = useCallback((value: Message | null | undefined) => translate(language, value), [language]);
  return { language, setLanguage, t };
}

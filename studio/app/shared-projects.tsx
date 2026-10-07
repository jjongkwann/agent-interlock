"use client";

import { useEffect, useRef, useState } from "react";
import { useLanguage } from "./language";
import "./shared-projects.css";

type Project = { id: string; revision: number; updatedAt: string; updatedBy: string; manifest?: unknown };
type Props = {
  open: boolean; onClose: () => void; apiUrl: string; token: string;
  rawManifest: string; projectId: string; onOpen: (manifest: unknown, source: string) => boolean;
};

export function SharedProjects({ open, onClose, apiUrl, token, rawManifest, projectId, onOpen }: Props) {
  const { language } = useLanguage();
  const copy = (en: string, ko: string) => language === "ko" ? ko : en;
  const dialog = useRef<HTMLDialogElement>(null);
  const request = useRef(0);
  const [projects, setProjects] = useState<Project[]>([]);
  const [revisions, setRevisions] = useState<Record<string, number>>({});
  const [target, setTarget] = useState<{ id: string; tenant: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("");
  useEffect(() => {
    if (open) dialog.current?.showModal();
    else dialog.current?.close();
  }, [open]);
  useEffect(() => () => { request.current += 1; }, []);

  async function call(path: string, init?: RequestInit) {
    const response = await fetch(`${apiUrl.replace(/\/$/, "")}${path}`, {
      ...init, headers: { Authorization: `Bearer ${token}`, ...(init?.body ? { "Content-Type": "application/json" } : {}) },
    });
    const body = await response.json();
    if (!response.ok) throw new Error(`${body.error?.code ?? response.status}: ${body.error?.message ?? "Request failed"}`);
    return body;
  }

  async function refresh() {
    const generation = ++request.current;
    setBusy(true); setStatus("");
    try {
      const [host, listing] = await Promise.all([call("/v1/runtime/status"), call("/v1/projects")]);
      if (generation !== request.current) return;
      if (!host.capabilities?.sharedProjects) throw new Error("Shared projects are unavailable on this host");
      if (target?.id !== host.targetId || target?.tenant !== host.tenantId) setRevisions({});
      setTarget({ id: host.targetId, tenant: host.tenantId });
      setProjects(listing.projects);
      setStatus(copy("Shared projects refreshed.", "공동 프로젝트 목록을 갱신했습니다."));
    } catch (error) { if (generation === request.current) { setTarget(null); setStatus(String(error)); } }
    finally { if (generation === request.current) setBusy(false); }
  }

  async function openProject(id: string) {
    const generation = ++request.current;
    setBusy(true);
    try {
      const { project } = await call(`/v1/projects/${encodeURIComponent(id)}`);
      if (generation !== request.current) return;
      if (onOpen(project.manifest, `${id} · shared revision ${project.revision}`)) {
        setRevisions(previous => ({ ...previous, [id]: project.revision }));
        setProjects(previous => [project, ...previous.filter(item => item.id !== id)]);
        setStatus("");
        onClose();
      } else setStatus(copy("The stored draft could not be opened. Export your current draft before repairing it.", "저장된 초안을 열 수 없습니다. 수정하기 전에 현재 초안을 내보내세요."));
    } catch (error) { if (generation === request.current) setStatus(String(error)); }
    finally { if (generation === request.current) setBusy(false); }
  }

  async function save() {
    const generation = ++request.current;
    const id = projectId;
    setBusy(true);
    try {
      const { project } = await call(`/v1/projects/${encodeURIComponent(id)}`, {
        method: "POST", body: JSON.stringify({ targetId: target?.id, revision: revisions[id] ?? 0, manifest: JSON.parse(rawManifest) }),
      });
      if (generation !== request.current) return;
      setRevisions(previous => ({ ...previous, [id]: project.revision }));
      setProjects(previous => [project, ...previous.filter(item => item.id !== id)]);
      setStatus(copy(`Saved ${id} · revision ${project.revision}`, `${id} 저장 완료 · 리비전 ${project.revision}`));
    } catch (error) { if (generation === request.current) setStatus(String(error)); }
    finally { if (generation === request.current) setBusy(false); }
  }

  return <dialog ref={dialog} className="shared-projects" onCancel={onClose} onClose={onClose} aria-labelledby="shared-project-title">
    <header><h2 id="shared-project-title">{copy("Shared projects", "공동 프로젝트")}</h2><button className="quiet-button" onClick={onClose}>{copy("Close", "닫기")}</button></header>
    <p>{copy("Connect in Deploy, then save drafts for your team. Open the current shared revision before editing an existing project.", "배포 화면에서 연결한 서버에 팀 초안을 저장합니다. 기존 프로젝트는 서버의 최신 리비전을 열고 수정하세요.")}</p>
    <p><code>{apiUrl}</code></p>
    {target && <p className="panel-note">Tenant: <code>{target.tenant}</code><br/>Target: <code>{target.id}</code></p>}
    <div className="shared-project-actions"><button className="secondary-button" disabled={busy || !token.trim()} onClick={() => void refresh()}>{copy("Refresh shared projects", "공동 목록 새로고침")}</button>
      <button className="primary-button" disabled={busy || !target || !projectId} onClick={() => void save()}>{copy("Save current draft", "현재 초안 서버에 저장")}</button></div>
    <p className="panel-note">{copy("If another editor saved first, your save is rejected. Save or export your local draft before opening the latest shared version to merge changes.", "다른 편집자가 먼저 저장하면 덮어쓰기를 거부합니다. 로컬 저장이나 내보내기로 작업을 보존한 뒤 최신 공동 버전을 열어 변경 사항을 합치세요.")}</p>
    {status && <p role="status">{status}</p>}
    <ul>{projects.map(project => <li key={project.id}><div><strong>{project.id}</strong><small>r{project.revision} · {project.updatedBy} · {new Date(project.updatedAt).toLocaleString()}</small></div><button className="secondary-button" disabled={busy} onClick={() => void openProject(project.id)}>{copy("Open", "열기")}</button></li>)}</ul>
    {target && projects.length === 0 && <p>{copy("No shared drafts are visible with this credential.", "이 인증 정보로 볼 수 있는 공동 초안이 없습니다.")}</p>}
  </dialog>;
}

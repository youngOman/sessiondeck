/**
 * Svelte store for project infrastructure state
 * (compose services + ports + bare dev servers, per project directory)
 */

import { writable, get } from 'svelte/store';
import { listen } from '@tauri-apps/api/event';
import type { InfraSnapshot } from '../types';
import { isDemoMode } from '../demo/mode';
import { getProjectInfra } from '../api';
import { wsClient, useWebSocket, getStoredWsUrl } from '../ws';

/**
 * Latest infra snapshot pushed by the backend (null until first fetch)
 */
export const infra = writable<InfraSnapshot | null>(null);

let initialized = false;

/**
 * Initialize infra listeners + initial fetch.
 * Safe to call from multiple entry points (layout, popover, connection screen).
 */
export async function initializeInfraListeners() {
	if (initialized) return;
	initialized = true;

	if (get(isDemoMode)) return;

	if (useWebSocket()) {
		wsClient.on('infraUpdated', (data: InfraSnapshot) => {
			if (!get(isDemoMode)) infra.set(data);
		});
	} else {
		await listen<InfraSnapshot>('infra-updated', (event) => {
			if (!get(isDemoMode)) infra.set(event.payload);
		});
	}

	try {
		infra.set(await getProjectInfra());
	} catch (e) {
		console.warn('[infra] Initial fetch failed:', e);
	}
}

/**
 * One clickable port chip on a session card
 */
export interface PortChip {
	label: string;
	hostPort: number;
	state: string;
	title: string;
}

/**
 * True when one directory contains the other (compose working_dir is often a
 * subdirectory of the session's project path, e.g. deployments/docker).
 */
function dirMatches(a: string, b: string): boolean {
	if (!a || !b) return false;
	return a === b || a.startsWith(b + '/') || b.startsWith(a + '/');
}

/**
 * Collect the port chips relevant to one session's project path:
 * compose services whose working_dir overlaps the project, plus bare dev
 * servers whose cwd overlaps it. Deduped by host port, sorted ascending.
 */
export function portChipsFor(snapshot: InfraSnapshot | null, projectPath: string): PortChip[] {
	if (!snapshot) return [];
	const chips: PortChip[] = [];

	for (const project of snapshot.composeProjects ?? []) {
		if (!dirMatches(project.workingDir, projectPath)) continue;
		const configNote = project.configFiles.length
			? `\n${project.configFiles.join('\n')}`
			: '';
		for (const svc of project.services) {
			for (const pm of svc.ports) {
				chips.push({
					label: svc.service,
					hostPort: pm.hostPort,
					state: svc.state,
					title: `${project.name} / ${svc.containerName} — ${pm.hostPort}→${pm.containerPort}/${pm.protocol} (${svc.state})${configNote}`
				});
			}
		}
	}

	for (const server of snapshot.bareServers ?? []) {
		if (!dirMatches(server.cwd, projectPath)) continue;
		chips.push({
			label: server.process,
			hostPort: server.port,
			state: 'running',
			title: `${server.process} (pid ${server.pid})\n${server.cwd}`
		});
	}

	chips.sort((a, b) => a.hostPort - b.hostPort);
	const seen = new Set<number>();
	return chips.filter((c) => (seen.has(c.hostPort) ? false : (seen.add(c.hostPort), true)));
}

/**
 * URL for a host port. On a remote web client, "localhost" would point at the
 * viewing device — use the desktop host from the stored WS URL instead.
 */
export function portUrl(port: number): string {
	let host = 'localhost';
	const wsUrl = useWebSocket() ? getStoredWsUrl() : null;
	if (wsUrl) {
		try {
			host = new URL(wsUrl).hostname || 'localhost';
		} catch {
			// keep localhost
		}
	}
	return `http://${host}:${port}`;
}

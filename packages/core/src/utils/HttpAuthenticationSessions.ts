/** In-memory OAuth caches scoped to open projects. Never serialize these caches into project/settings storage. */
export class HttpAuthenticationSessions {
  private readonly projects = new Map<string, Map<string, unknown>>();

  forProject(projectId: string): Map<string, unknown> {
    let cache = this.projects.get(projectId);
    if (!cache) {
      cache = new Map();
      this.projects.set(projectId, cache);
    }
    return cache;
  }

  retain(projectIds: Iterable<string>): void {
    const open = new Set(projectIds);
    for (const [projectId, cache] of this.projects) {
      if (!open.has(projectId)) {
        cache.clear();
        this.projects.delete(projectId);
      }
    }
  }

  clear(): void {
    this.retain([]);
  }
}

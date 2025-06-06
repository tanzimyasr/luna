// This class periodically checks /api/health to determine the reachability of the different parts of the application.
// It also checks /api/version to determine the compatibility of the frontend with the backend.

import { browser } from "$app/environment";
import { FRONTEND_VERSION, isCompatibleWithBackend, VersionCompatibility } from "$lib/common/version";
import { fetchJson } from "./net";

export enum Reachability {
  Unknown,
  Incompatible,
  None,
  Frontend,
  Backend,
  Database
}

class Connectivity {
  reachable = $state<Reachability>(Reachability.Unknown);

  private compatibility: VersionCompatibility;
  private backendVersion: string | null;

  private promise: Promise<Reachability> | null;
  
  constructor() {
    this.reachable = Reachability.Database;
    this.compatibility = VersionCompatibility.Unknown;
    this.backendVersion = null;
    this.promise = null;
  }

  private async checkConnection() {
    await fetchJson("/api/health").then(async () => {
      this.reachable = Reachability.Database

      const compatibility = await this.checkVersion();
      if ([VersionCompatibility.BackendOutdatedMajor, VersionCompatibility.FrontendOutdatedMajor].includes(compatibility)) {
        this.reachable = Reachability.Incompatible;
      }
    }).catch((err) => {
      if (err.message === "Could not contact server" || err.message.includes("NetworkError")) {
        this.reachable = Reachability.None;
      } else if (err.message === "The backend is not reachable") {
        this.reachable = Reachability.Frontend;
      } else if (err.message === "The database is not reachable") {
        this.reachable = Reachability.Backend;
      } else {
        this.reachable = Reachability.Unknown;
      }
    })

    this.promise = null;
    return this.reachable;
  }

  async check() {
    if (this.promise === null) {
      this.promise = this.checkConnection();
    }

    return this.promise;
  }

  private async checkVersion() {
    const version = await fetchJson("/api/version").catch(() => {
      return null;
    });

    this.backendVersion = version.version;
    this.compatibility = isCompatibleWithBackend(version.version);

    if (
      browser &&
      document.location.pathname !== "/version" &&
      [VersionCompatibility.BackendOutdatedMajor, VersionCompatibility.FrontendOutdatedMajor].includes(this.compatibility)
    ) {
      document.location.href = `/version?redirect=${encodeURIComponent(new URL(document.location.href).pathname)}`;
    } 

    return this.compatibility;
  }

  async getVersions(): Promise<{ frontend: string, backend: string, compatibility: VersionCompatibility }> {
    await this.checkVersion();


    return {
      frontend: FRONTEND_VERSION,
      backend: this.backendVersion || "unknown",
      compatibility: this.compatibility
    }
  }

  setPrefetchedVersion(prefetchedVersion: string) {
    this.backendVersion = prefetchedVersion;
    this.compatibility = isCompatibleWithBackend(prefetchedVersion);
  }
}

let connectivity: Connectivity | null = $state(null);
export function getConnectivity(prefetchedVersion: string = ""): Connectivity {
  if (connectivity === null) connectivity = new Connectivity();
  if (prefetchedVersion !== "") connectivity.setPrefetchedVersion(prefetchedVersion);
  return connectivity;
}

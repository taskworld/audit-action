export type LicenseAuditOptions = {
  path: string
  includeDevDependencies?: boolean
  excludeLicenses?: string[]
  excludePrivatePackages?: boolean
  excludePackageScopes?: string[]
  excludePackages?: string[]
}

export type LicenseAuditReportResult = {
  packageName: string
  packageVersion: string
  licenseName: string
  licenseFile?: string
  repository?: string
}

export type LicenseAuditReport = {
  licenses: LicenseAuditReportResult[]
}

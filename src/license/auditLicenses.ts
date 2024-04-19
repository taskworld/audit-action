import { promisify } from 'util'
import checker from 'license-checker'

import type { LicenseAuditOptions, LicenseAuditReport, LicenseAuditReportResult } from './types.js'

export async function auditLicenses(options: LicenseAuditOptions) {
  const licenseInfo = await promisify(checker.init)({
    start: options.path,
    relativeLicensePath: true,
    excludePrivatePackages: options?.excludePrivatePackages ?? false,

    // @ts-expect-error type declared in checker.init is wrong
    exclude: options.excludeLicenses?.length ? options.excludeLicenses.join(',') : undefined,

    excludePackages: options.excludePackages?.length
      ? options.excludePackages.join(';')
      : undefined,

    production: !!options?.includeDevDependencies,
  })

  const packages = Object.entries(licenseInfo).map(([packageId, license]) => {
    const splitIdx = packageId.lastIndexOf('@')
    const packageName = packageId.slice(0, splitIdx)
    const packageVersion = packageId.slice(splitIdx + 1)

    return {
      packageName,
      packageVersion,
      licenseName: license.licenses ?? 'UNKNOWN',
      ...(license.licenseFile && { licenseFile: license.licenseFile }),
      ...(license.repository && { repository: license.repository }),
    } as LicenseAuditReportResult
  })

  const filteredPackages = options?.excludePackageScopes?.length
    ? packages.filter((pkg) => {
        if (pkg.packageName.startsWith('@')) {
          const scope = pkg.packageName.slice(0, pkg.packageName.indexOf('/'))

          return !options?.excludePackageScopes?.includes(scope)
        }

        return true
      })
    : packages

  return { licenses: filteredPackages } as LicenseAuditReport
}

import { findWorkspaces } from '@taskworld/workspaces'
import { auditDependencies, DependencyAuditOptions } from '@taskworld/platform-audit'

interface AuditWorkspacesOptions extends Omit<DependencyAuditOptions, 'path'> {
  rootWorkspacePath: string
}

// WIP
export async function auditWorkspaces(options: AuditWorkspacesOptions): Promise<string> {
  // find workspaces
  const workspaces = await findWorkspaces(options.rootWorkspacePath)

  const reports = await Promise.all(
    workspaces.map(async (workspace) => auditDependencies({ ...options, path: workspace.path })),
  )

  return ''
}

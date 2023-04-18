"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.auditWorkspaces = void 0;
const workspaces_1 = require("@taskworld/workspaces");
const platform_audit_1 = require("@taskworld/platform-audit");
// WIP
function auditWorkspaces(options) {
    return __awaiter(this, void 0, void 0, function* () {
        // find workspaces
        const workspaces = yield (0, workspaces_1.findWorkspaces)(options.rootWorkspacePath);
        const reports = yield Promise.all(workspaces.map((workspace) => __awaiter(this, void 0, void 0, function* () { return (0, platform_audit_1.auditDependencies)(Object.assign(Object.assign({}, options), { path: workspace.path })); })));
        return '';
    });
}
exports.auditWorkspaces = auditWorkspaces;

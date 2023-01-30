"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
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
exports.auditPR = void 0;
const platform_audit_1 = require("@taskworld/platform-audit");
const core = __importStar(require("@actions/core"));
function auditPR(options, identifier) {
    return __awaiter(this, void 0, void 0, function* () {
        core.info(`Options: ${JSON.stringify(options, null, 2)}`);
        const report = yield (0, platform_audit_1.auditDependencies)(options);
        core.info(`Report: ${JSON.stringify(report, null, 2)}`);
        const numVulnabilities = Object.keys(report.vulnerabilities).reduce((total, level) => {
            return total + report.vulnerabilities[level];
        }, 0);
        if (numVulnabilities < 1) {
            const noVulnerabilities = `
✅ No vulnerabilities found in **${identifier}**.
`;
            return { vulnerabilities: noVulnerabilities };
        }
        const renderedVulnerabilities = `
## Vulnerabilities 

Vulnerabilities were found in **${identifier}**.

<table>
  <tbody>
    <tr>
      <th align="left">🔴 Critical</th>
      <td>${report.vulnerabilities.critical}</td>
    </tr>
    <tr>
      <th align="left">🟡 High</th>
      <td>${report.vulnerabilities.high}</td>
    </tr>
    <tr>
      <th align="left">⚪ Moderate</th>
      <td>${report.vulnerabilities.moderate}</td>
    </tr>
  </tbody>
</table>`;
        return { vulnerabilities: renderedVulnerabilities };
    });
}
exports.auditPR = auditPR;

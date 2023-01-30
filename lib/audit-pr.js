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
exports.auditPR = void 0;
const platform_audit_1 = require("@taskworld/platform-audit");
function auditPR(options, identifier) {
    return __awaiter(this, void 0, void 0, function* () {
        const report = yield (0, platform_audit_1.auditDependencies)(options);
        const numVulnabilities = Object.keys(report.vulnerabilities).reduce((total, level) => {
            return total + report.vulnerabilities[level];
        }, 0);
        if (numVulnabilities < 1) {
            return { vulnerabilities: null };
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

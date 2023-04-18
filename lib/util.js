"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.auditReportHasVulnerabilities = exports.countVulnerabilities = void 0;
const LEVELS = ['info', 'low', 'moderate', 'high', 'critical'];
function countVulnerabilities(report) {
    return Object.keys(report.vulnerabilities).reduce((total, level) => {
        return total + report.vulnerabilities[level];
    }, 0);
}
exports.countVulnerabilities = countVulnerabilities;
function auditReportHasVulnerabilities(report, level = 'info') {
    const inferredLevels = LEVELS.slice(LEVELS.indexOf(level));
    return inferredLevels.some((level) => report.vulnerabilities[level] > 0);
}
exports.auditReportHasVulnerabilities = auditReportHasVulnerabilities;

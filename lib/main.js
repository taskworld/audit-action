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
const core = __importStar(require("@actions/core"));
const github_1 = require("@actions/github");
const audit_pr_1 = require("./audit-pr");
function run() {
    var _a, _b, _c;
    return __awaiter(this, void 0, void 0, function* () {
        try {
            const path = (_a = core.getInput('path')) !== null && _a !== void 0 ? _a : process.env.GITHUB_WORKSPACE;
            const packageManager = (_b = core.getInput('package-manager')) !== null && _b !== void 0 ? _b : 'pnpm';
            const identifier = (_c = core.getInput('identifier')) !== null && _c !== void 0 ? _c : github_1.context.repo.repo;
            if (github_1.context.eventName === 'pull_request') {
                const failureLevel = core.getInput('failureLevel') !== ''
                    ? core.getInput('failureLevel')
                    : undefined;
                const result = yield (0, audit_pr_1.auditPR)({ packageManager, path, level: 'moderate' }, identifier, failureLevel);
                core.setOutput('vulnerabilities', result.vulnerabilities);
                core.setOutput('failed', result.failed);
            }
        }
        catch (error) {
            if (error instanceof Error)
                core.setFailed(error.message);
        }
    });
}
run();

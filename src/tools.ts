import { z } from 'zod';
import { ExpensifyClient } from './api-client.js';

/**
 * Expensify MCP Tool Definitions
 *
 * 13 tools covering: Reports, Expenses, Policies,
 * Categories, Tags, Reconciliation, Downloads
 */

interface ToolDef {
  name: string;
  description: string;
  inputSchema: z.ZodType<any>;
  handler: (client: ExpensifyClient, args: any) => Promise<any>;
}

export const tools: ToolDef[] = [
  // --- Reports (3) ---
  {
    name: 'reports_export',
    description: 'Export expense reports for a date range',
    inputSchema: z.object({
      startDate: z.string().describe('start date (yyyy-MM-dd)'),
      endDate: z.string().describe('end date (yyyy-MM-dd)'),
      reportState: z.enum([
        'OPEN', 'SUBMITTED', 'APPROVED', 'REIMBURSED', 'ARCHIVED',
      ]).optional().describe('filter by report state'),
      limit: z.string().optional().describe('max reports to export'),
      employeeEmail: z.string().optional().describe('filter by submitter'),
      markedAsExported: z.string().optional().describe('export tag filter'),
    }),
    handler: async (client: ExpensifyClient, args: any) =>
      client.exportReports(args),
  },
  {
    name: 'report_create',
    description: 'Create expense report with transactions',
    inputSchema: z.object({
      employeeEmail: z.string().describe('submitter email'),
      expenses: z.string().describe('JSON array of expense objects'),
    }),
    handler: async (client: ExpensifyClient, args: any) =>
      client.createReport(args),
  },
  {
    name: 'report_status_update',
    description: 'Update report status (mark as exported)',
    inputSchema: z.object({
      reportIDList: z.string().describe('comma-separated report IDs'),
      status: z.enum(['EXPORTED', 'APPROVED', 'REIMBURSED']).describe('new status'),
    }),
    handler: async (client: ExpensifyClient, args: any) =>
      client.updateReportStatus({
        reportIDList: args.reportIDList.split(',').map((s: string) => s.trim()),
        status: args.status,
      }),
  },

  // --- Files (1) ---
  {
    name: 'file_download',
    description: 'Download a previously exported file',
    inputSchema: z.object({
      fileName: z.string().describe('filename from export result'),
      fileSystem: z.string().optional().describe('file system (default: integrationServer)'),
    }),
    handler: async (client: ExpensifyClient, args: any) =>
      client.downloadFile(args.fileName, args.fileSystem),
  },

  // --- Policies (2) ---
  {
    name: 'policies_list',
    description: 'List accessible policies',
    inputSchema: z.object({
      adminOnly: z.boolean().optional().describe('only admin policies'),
    }),
    handler: async (client: ExpensifyClient, args: any) =>
      client.getPolicyList(args.adminOnly),
  },
  {
    name: 'policy_get',
    description: 'Get policy details by ID',
    inputSchema: z.object({
      policyID: z.string().describe('policy ID'),
      fields: z.string().optional().describe('comma-separated fields: categories,tags,reportFields,employees'),
    }),
    handler: async (client: ExpensifyClient, args: any) =>
      client.getPolicyDetails({
        policyIDList: [args.policyID],
        fields: args.fields ? args.fields.split(',').map((s: string) => s.trim()) : undefined,
      }),
  },

  // --- Categories (2) ---
  {
    name: 'categories_get',
    description: 'Get expense categories for a policy',
    inputSchema: z.object({
      policyID: z.string().describe('policy ID'),
    }),
    handler: async (client: ExpensifyClient, args: any) =>
      client.getCategories(args.policyID),
  },
  {
    name: 'categories_update',
    description: 'Update categories on a policy',
    inputSchema: z.object({
      policyID: z.string().describe('policy ID'),
      categories: z.string().describe('JSON category data'),
    }),
    handler: async (client: ExpensifyClient, args: any) =>
      client.updateCategories(args),
  },

  // --- Tags (2) ---
  {
    name: 'tags_get',
    description: 'Get tags for a policy',
    inputSchema: z.object({
      policyID: z.string().describe('policy ID'),
    }),
    handler: async (client: ExpensifyClient, args: any) =>
      client.getTags(args.policyID),
  },
  {
    name: 'tags_update',
    description: 'Update tags on a policy',
    inputSchema: z.object({
      policyID: z.string().describe('policy ID'),
      tags: z.string().describe('JSON tag data'),
    }),
    handler: async (client: ExpensifyClient, args: any) =>
      client.updateTags(args),
  },

  // --- Reconciliation (1) ---
  {
    name: 'reconciliation_get',
    description: 'Export corporate card reconciliation data',
    inputSchema: z.object({
      startDate: z.string().describe('start date (yyyy-MM-dd)'),
      endDate: z.string().describe('end date (yyyy-MM-dd)'),
      domain: z.string().optional().describe('company domain'),
    }),
    handler: async (client: ExpensifyClient, args: any) =>
      client.getReconciliation(args),
  },

  // --- Domain Cards (1) ---
  {
    name: 'domain_cards_list',
    description: 'List corporate card feeds for a domain',
    inputSchema: z.object({
      domain: z.string().describe('company domain name'),
    }),
    handler: async (client: ExpensifyClient, args: any) =>
      client.getDomainCards(args.domain),
  },

  // --- Advanced Export (1) ---
  {
    name: 'reports_export_custom',
    description: 'Export reports with custom Freemarker template',
    inputSchema: z.object({
      startDate: z.string().describe('start date (yyyy-MM-dd)'),
      endDate: z.string().describe('end date (yyyy-MM-dd)'),
      template: z.string().describe('Freemarker template string'),
      outputFormat: z.string().optional().describe('file extension (csv, json, txt)'),
      reportState: z.enum([
        'OPEN', 'SUBMITTED', 'APPROVED', 'REIMBURSED', 'ARCHIVED',
      ]).optional().describe('filter by report state'),
      employeeEmail: z.string().optional().describe('filter by submitter'),
    }),
    handler: async (client: ExpensifyClient, args: any) =>
      client.exportReports(args),
  },
];

#!/usr/bin/env node
import { createApp } from './app.js';
const port = Number.parseInt(process.env.PORT || '3100', 10);
const { app } = createApp();
app.listen(port, () => console.log('Expensify MCP Server listening. Every MCP request requires authentication.'));

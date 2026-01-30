import * as vscode from 'vscode';
import * as path from 'path';
import {
    LanguageClient,
    LanguageClientOptions,
    ServerOptions,
    TransportKind
} from 'vscode-languageclient/node';

let client: LanguageClient | undefined;
let outputChannel: vscode.OutputChannel;

export async function activate(context: vscode.ExtensionContext) {
    outputChannel = vscode.window.createOutputChannel('RMA');
    outputChannel.appendLine('RMA extension activating...');

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('rma.analyzeFile', analyzeCurrentFile),
        vscode.commands.registerCommand('rma.analyzeWorkspace', analyzeWorkspace),
        vscode.commands.registerCommand('rma.showOutput', () => outputChannel.show()),
        vscode.commands.registerCommand('rma.restartServer', restartServer)
    );

    // Start language server if enabled
    const config = vscode.workspace.getConfiguration('rma');
    if (config.get<boolean>('enableLsp', true)) {
        await startLanguageServer(context);
    }

    // Register file watchers if configured
    if (config.get<boolean>('analyzeOnSave', true)) {
        context.subscriptions.push(
            vscode.workspace.onDidSaveTextDocument(async (document) => {
                if (shouldAnalyze(document)) {
                    await analyzeDocument(document);
                }
            })
        );
    }

    if (config.get<boolean>('analyzeOnOpen', true)) {
        context.subscriptions.push(
            vscode.workspace.onDidOpenTextDocument(async (document) => {
                if (shouldAnalyze(document)) {
                    await analyzeDocument(document);
                }
            })
        );
    }

    outputChannel.appendLine('RMA extension activated');
}

export async function deactivate(): Promise<void> {
    if (client) {
        await client.stop();
    }
}

async function startLanguageServer(context: vscode.ExtensionContext): Promise<void> {
    const config = vscode.workspace.getConfiguration('rma');
    let serverPath = config.get<string>('serverPath', '');

    // Find server executable
    if (!serverPath) {
        // Try bundled server first
        const bundledPath = context.asAbsolutePath(
            path.join('server', process.platform === 'win32' ? 'rma-lsp.exe' : 'rma-lsp')
        );

        try {
            await vscode.workspace.fs.stat(vscode.Uri.file(bundledPath));
            serverPath = bundledPath;
        } catch {
            // Fall back to PATH
            serverPath = 'rma-lsp';
        }
    }

    outputChannel.appendLine(`Starting language server: ${serverPath}`);

    const serverOptions: ServerOptions = {
        command: serverPath,
        transport: TransportKind.stdio,
        args: []
    };

    const clientOptions: LanguageClientOptions = {
        documentSelector: [
            { scheme: 'file', language: 'rust' },
            { scheme: 'file', language: 'javascript' },
            { scheme: 'file', language: 'typescript' },
            { scheme: 'file', language: 'python' },
            { scheme: 'file', language: 'go' },
            { scheme: 'file', language: 'java' }
        ],
        synchronize: {
            fileEvents: vscode.workspace.createFileSystemWatcher('**/*.{rs,js,ts,py,go,java}')
        },
        outputChannel
    };

    client = new LanguageClient(
        'rma',
        'RMA Language Server',
        serverOptions,
        clientOptions
    );

    try {
        await client.start();
        outputChannel.appendLine('Language server started');
    } catch (error) {
        outputChannel.appendLine(`Failed to start language server: ${error}`);
        vscode.window.showErrorMessage(
            'Failed to start RMA language server. Make sure rma-lsp is installed.',
            'Install Instructions'
        ).then(selection => {
            if (selection === 'Install Instructions') {
                vscode.env.openExternal(vscode.Uri.parse(
                    'https://github.com/bumahkib7/rust-monorepo-analyzer#installation'
                ));
            }
        });
    }
}

async function restartServer(): Promise<void> {
    outputChannel.appendLine('Restarting language server...');
    if (client) {
        await client.stop();
        client = undefined;
    }
    const context = await vscode.extensions.getExtension('rma.rma-vscode')?.activate();
    if (context) {
        await startLanguageServer(context);
    }
}

function shouldAnalyze(document: vscode.TextDocument): boolean {
    const config = vscode.workspace.getConfiguration('rma');
    const supportedLanguages = ['rust', 'javascript', 'typescript', 'python', 'go', 'java'];

    if (!supportedLanguages.includes(document.languageId)) {
        return false;
    }

    // Check file size
    const maxSizeKb = config.get<number>('maxFileSizeKb', 1024);
    // Estimate size from text length (rough approximation)
    if (document.getText().length / 1024 > maxSizeKb) {
        return false;
    }

    // Check exclude patterns
    const excludePatterns = config.get<string[]>('excludePatterns', []);
    const relativePath = vscode.workspace.asRelativePath(document.uri);

    for (const pattern of excludePatterns) {
        const regex = globToRegex(pattern);
        if (regex.test(relativePath)) {
            return false;
        }
    }

    return true;
}

function globToRegex(glob: string): RegExp {
    const escaped = glob
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\*\*/g, '.*')
        .replace(/\*/g, '[^/]*')
        .replace(/\?/g, '.');
    return new RegExp(`^${escaped}$`);
}

async function analyzeCurrentFile(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No active file to analyze');
        return;
    }
    await analyzeDocument(editor.document);
}

async function analyzeDocument(document: vscode.TextDocument): Promise<void> {
    if (!client) {
        vscode.window.showWarningMessage('RMA language server is not running');
        return;
    }

    outputChannel.appendLine(`Analyzing: ${document.uri.fsPath}`);

    // The language server handles analysis automatically
    // This is just a manual trigger that could force a refresh
    await client.sendNotification('textDocument/didChange', {
        textDocument: {
            uri: document.uri.toString(),
            version: document.version
        },
        contentChanges: [{
            text: document.getText()
        }]
    });
}

async function analyzeWorkspace(): Promise<void> {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) {
        vscode.window.showWarningMessage('No workspace folder open');
        return;
    }

    outputChannel.appendLine('Analyzing workspace...');

    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'RMA: Analyzing workspace',
        cancellable: true
    }, async (progress, token) => {
        const files = await vscode.workspace.findFiles(
            '**/*.{rs,js,ts,py,go,java}',
            '**/node_modules/**,**/target/**'
        );

        const total = files.length;
        let processed = 0;

        for (const file of files) {
            if (token.isCancellationRequested) {
                break;
            }

            const document = await vscode.workspace.openTextDocument(file);
            if (shouldAnalyze(document)) {
                await analyzeDocument(document);
            }

            processed++;
            progress.report({
                message: `${processed}/${total} files`,
                increment: (1 / total) * 100
            });
        }

        outputChannel.appendLine(`Workspace analysis complete: ${processed} files processed`);
    });
}

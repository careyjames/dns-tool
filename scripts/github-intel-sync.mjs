import { Octokit } from '@octokit/rest';

const INTEL_REPO_OWNER = 'IT-Help-San-Diego';
const INTEL_REPO_NAME = 'dns-tool';
const INTEL_BRANCH = 'main';

let connectionSettings = null;

async function getAccessToken() {
  if (connectionSettings && connectionSettings.settings.expires_at && new Date(connectionSettings.settings.expires_at).getTime() > Date.now()) {
    return connectionSettings.settings.access_token;
  }

  const hostname = process.env.REPLIT_CONNECTORS_HOSTNAME;
  const xReplitToken = process.env.REPL_IDENTITY
    ? 'repl ' + process.env.REPL_IDENTITY
    : process.env.WEB_REPL_RENEWAL
    ? 'depl ' + process.env.WEB_REPL_RENEWAL
    : null;

  if (!xReplitToken) {
    throw new Error('X_REPLIT_TOKEN not found');
  }

  connectionSettings = await fetch(
    'https://' + hostname + '/api/v2/connection?include_secrets=true&connector_names=github',
    {
      headers: {
        'Accept': 'application/json',
        'X_REPLIT_TOKEN': xReplitToken
      }
    }
  ).then(res => res.json()).then(data => data.items?.[0]);

  const accessToken = connectionSettings?.settings?.access_token || connectionSettings.settings?.oauth?.credentials?.access_token;

  if (!connectionSettings || !accessToken) {
    throw new Error('GitHub not connected');
  }
  return accessToken;
}

async function getClient() {
  const accessToken = await getAccessToken();
  return new Octokit({ auth: accessToken });
}

async function listIntelFiles() {
  const octokit = await getClient();
  const result = [];

  async function listDir(path) {
    try {
      const { data } = await octokit.repos.getContent({
        owner: INTEL_REPO_OWNER,
        repo: INTEL_REPO_NAME,
        path: path,
        ref: INTEL_BRANCH,
      });
      if (Array.isArray(data)) {
        for (const item of data) {
          if (item.type === 'dir') {
            await listDir(item.path);
          } else {
            result.push({ path: item.path, sha: item.sha, size: item.size });
          }
        }
      }
    } catch (e) {
      if (e.status !== 404) throw e;
    }
  }

  await listDir('');
  return result;
}

async function getFile(path) {
  const octokit = await getClient();
  const { data } = await octokit.repos.getContent({
    owner: INTEL_REPO_OWNER,
    repo: INTEL_REPO_NAME,
    path: path,
    ref: INTEL_BRANCH,
  });
  if (data.encoding === 'base64') {
    return { content: Buffer.from(data.content, 'base64').toString('utf8'), sha: data.sha };
  }
  return { content: data.content, sha: data.sha };
}

async function putFile(path, content, message, existingSha) {
  const octokit = await getClient();
  const params = {
    owner: INTEL_REPO_OWNER,
    repo: INTEL_REPO_NAME,
    path: path,
    message: message,
    content: Buffer.from(content).toString('base64'),
    branch: INTEL_BRANCH,
  };
  if (existingSha) {
    params.sha = existingSha;
  }
  const { data } = await octokit.repos.createOrUpdateFileContents(params);
  return { sha: data.content.sha, commit: data.commit.sha };
}

async function deleteFile(path, message, sha) {
  const octokit = await getClient();
  await octokit.repos.deleteFile({
    owner: INTEL_REPO_OWNER,
    repo: INTEL_REPO_NAME,
    path: path,
    message: message,
    sha: sha,
    branch: INTEL_BRANCH,
  });
}

async function getCommits(perPage = 10) {
  const octokit = await getClient();
  const { data } = await octokit.repos.listCommits({
    owner: INTEL_REPO_OWNER,
    repo: INTEL_REPO_NAME,
    sha: INTEL_BRANCH,
    per_page: perPage,
  });
  return data.map(c => ({
    sha: c.sha.substring(0, 7),
    message: c.commit.message,
    date: c.commit.committer.date,
    author: c.commit.author.name,
  }));
}

const cmd = process.argv[2];

switch (cmd) {
  case 'list': {
    const files = await listIntelFiles();
    console.log(`\n=== dnstool-intel file listing (${files.length} files) ===`);
    for (const f of files) {
      console.log(`  ${f.path} (${f.size} bytes)`);
    }
    break;
  }
  case 'read': {
    const filePath = process.argv[3];
    if (!filePath) { console.error('Usage: node github-intel-sync.mjs read <path>'); process.exit(1); }
    const { content } = await getFile(filePath);
    console.log(content);
    break;
  }
  case 'push': {
    const localPath = process.argv[3];
    const remotePath = process.argv[4];
    const message = process.argv[5] || `Update ${remotePath}`;
    if (!localPath || !remotePath) { console.error('Usage: node github-intel-sync.mjs push <local-path> <remote-path> [message]'); process.exit(1); }
    const fs = await import('fs');
    const content = fs.readFileSync(localPath, 'utf8');
    let existingSha = null;
    try {
      const existing = await getFile(remotePath);
      existingSha = existing.sha;
    } catch (e) {
      if (e.status !== 404) throw e;
    }
    const result = await putFile(remotePath, content, message, existingSha);
    console.log(`Pushed ${localPath} → ${INTEL_REPO_OWNER}/${INTEL_REPO_NAME}/${remotePath}`);
    console.log(`  Commit: ${result.commit}`);
    break;
  }
  case 'delete': {
    const delPath = process.argv[3];
    const delMsg = process.argv[4] || `Delete ${delPath}`;
    if (!delPath) { console.error('Usage: node github-intel-sync.mjs delete <remote-path> [message]'); process.exit(1); }
    const { sha } = await getFile(delPath);
    await deleteFile(delPath, delMsg, sha);
    console.log(`Deleted ${INTEL_REPO_OWNER}/${INTEL_REPO_NAME}/${delPath}`);
    break;
  }
  case 'commits': {
    const count = parseInt(process.argv[3] || '10');
    const commits = await getCommits(count);
    console.log(`\n=== dnstool-intel recent commits ===`);
    for (const c of commits) {
      console.log(`  ${c.sha} ${c.date} ${c.message}`);
    }
    break;
  }
  default:
    console.log('Usage: node scripts/github-intel-sync.mjs <command>');
    console.log('Commands:');
    console.log('  list                              List all files in Intel repo');
    console.log('  read <path>                       Read a file from Intel repo');
    console.log('  push <local> <remote> [message]   Push local file to Intel repo');
    console.log('  delete <path> [message]           Delete file from Intel repo');
    console.log('  commits [count]                   Show recent commits');
}

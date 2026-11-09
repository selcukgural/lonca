import React from 'react';
import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';
import CodeBlock from '@theme/CodeBlock';
import useBaseUrl from '@docusaurus/useBaseUrl';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';

const flow = [
  'agent leases symbols',
  'edits its workspace',
  'proposes',
  'daemon decides',
  'queue verifies and merges',
  'auditor replays',
];

const features = [
  {
    title: 'One deterministic gatekeeper',
    text:
      'Agents never write to the repository. They propose; a daemon decides with a pure function of the log, the request, recorded evidence, time and the repository’s policy. No AI, no network, no randomness in the decision.',
  },
  {
    title: 'Capabilities, not accounts',
    text:
      'A session gets narrow, expiring rights: paths, symbols, operations, size limits. Rights only narrow when handed to sub-agents, and revoking a session revokes everything derived from it. Agents hold no long-lived keys.',
  },
  {
    title: 'Symbol leases and a structural merge queue',
    text:
      'Agents lease the functions and types they edit, so twenty agents can change twenty functions of one file in parallel. Every merged state is built and tested in a sandbox before it becomes trunk.',
  },
  {
    title: 'A signed log anyone can replay',
    text:
      'Every operation, allowed, denied or escalated, is in a hash-chained, signed log that travels with git push. An independent auditor replays every decision and recomputes every fact and merge, and catches forgeries even when signed with the daemon’s own key.',
  },
  {
    title: 'Plain Git underneath',
    text:
      'Content stays Git: GitHub and every Git tool keep working. Humans can work in a Lonca workspace or in their own Git checkout; Lonca’s records live in refs/lonca/*.',
  },
  {
    title: 'Humans approve, with presence when it matters',
    text:
      'People review, approve, undo and revert. Approvals are signed with a file key or a Secure Enclave key with Touch ID; a hardened install runs the daemon as its own system user, out of the agents’ reach.',
  },
];

// What Claude Code gets from Lonca, one hook or tool each
// (docs/guide/claude-code.md has the whole table).
const claudeCode = [
  {
    mark: 'SessionStart',
    title: 'The rules from the first turn',
    text: 'The session is bound to the daemon; the repository, the level and the rules are in the context before the agent does anything.',
  },
  {
    mark: 'PreToolUse',
    title: 'Writes stay in the workspace',
    text: 'A write outside the workspace, to .lonca/ or to Lonca’s own files is denied before it happens. Fetches and shell commands are observed.',
  },
  {
    mark: 'PostToolUse',
    title: 'Every write on the record',
    text: 'Writes are recorded as they happen, and news from other agents arrives mid-turn: a lease handed over, a change integrated.',
  },
  {
    mark: 'Stop',
    title: 'No “done” with work left over',
    text: 'An agent that stops with unproposed changes is sent back to propose them, a bounded number of times.',
  },
  {
    mark: 'lonca mcp',
    title: 'Leases, proposals, sync',
    text: 'Lonca’s tools are approved for the agent. While it runs, heartbeats go out and its leases renew themselves.',
  },
  {
    mark: 'onFailure: block',
    title: 'Fails closed, proves it ran',
    text: 'A hook that can not reach the daemon blocks the tool. A call to Lonca that skipped its hook marks the session.',
  },
];

// Where each harness stands. Claude Code is checked in every release; the
// others have profiles (crates/lonca-policy/src/harnesses.toml).
const harnesses = [
  {
    name: 'Claude Code',
    status: 'Full support',
    tone: 'full',
    text: 'Every hook event, the MCP server, managed settings for the hardened level, lonca run for isolated. Run live before every release.',
  },
  {
    name: 'Codex',
    status: 'Full support coming',
    tone: 'soon',
    text: 'Profile included: rules, MCP and hooks set up for you. Sessions are unobserved until its hooks can be shown to hold; isolated under lonca run.',
  },
  {
    name: 'Gemini CLI',
    status: 'Full support coming',
    tone: 'soon',
    text: 'Profile included, same as Codex: everything set up, changes wait for a person, isolated under lonca run.',
  },
  {
    name: 'OpenCode',
    status: 'Full support coming',
    tone: 'soon',
    text: 'Profile and plugin included, stop event through its idle hook. Isolated under lonca run.',
  },
  {
    name: 'IDE agents',
    status: 'Planned',
    tone: 'planned',
    text: 'GitHub Copilot, Cursor, JetBrains AI: any MCP client can use lonca mcp today, unobserved. Profiles and live runs to come.',
  },
  {
    name: 'Your harness',
    status: 'Data, not code',
    tone: 'data',
    text: 'A harness is a table in the signed policy: its events, its tools, its setup. A new one needs no new Lonca.',
  },
];

const installLine = 'curl -fsSL https://selcukgural.github.io/lonca/install.sh | sh';

// Copies `text` the old way, for a browser without the Clipboard API (or
// a page not served over HTTPS): a selected, hidden text area.
function copyByHand(text) {
  const area = document.createElement('textarea');
  area.value = text;
  area.setAttribute('readonly', '');
  area.style.position = 'fixed';
  area.style.opacity = '0';
  document.body.appendChild(area);
  area.select();
  let copied = false;
  try {
    copied = document.execCommand('copy');
  } catch (e) {
    copied = false;
  }
  document.body.removeChild(area);
  return copied;
}

function InstallLine() {
  const [copied, setCopied] = React.useState(false);
  const done = () => {
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  const copy = () => {
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(installLine).then(done, () => {
        if (copyByHand(installLine)) done();
      });
    } else if (copyByHand(installLine)) {
      done();
    }
  };
  return (
    <div className="lonca-install">
      <span className="lonca-install-label">macOS and Linux, x86_64 and arm64</span>
      <div className="lonca-install-line">
        <code>
          <span className="lonca-install-prompt" aria-hidden="true">
            ${' '}
          </span>
          {installLine}
        </code>
        <button
          type="button"
          className="lonca-install-copy"
          onClick={copy}
          aria-label="Copy the install command">
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
    </div>
  );
}

const session = `lonca daemon &                       # the gatekeeper (~/.lonca)
lonca human keygen ayse              # or: --secure-enclave
lonca init demo --import ~/src/myproject

# Give an agent a session and a workspace.
lonca session start --repo demo --agent claude --paths 'src/**' \\
      --task T-142 --ttl 2h --workspace ~/ws/claude-1

# In the workspace, the agent (directly or through \`lonca mcp\`):
lonca lease acquire 'src/billing.rs#Client.charge' -i "rate limiting"
lonca propose -i "rate limit charge" --edits 'src/billing.rs#Client.charge'

# You review and operate:
lonca pending --repo demo
lonca approve 17 --repo demo
lonca-audit verify ~/.lonca/repos/demo.git`;

const other = `brew tap selcukgural/lonca                    # Homebrew (macOS, Linux)
brew install lonca
cargo install --locked lonca lonca-audit      # crates.io, Rust 1.90+`;

function ClaudeCode() {
  return (
    <section className="lonca-claude">
      <div className="container">
        <div className="lonca-section-head">
          <span className="lonca-eyebrow">Works with Claude Code</span>
          <h2>Every hook, every tool, every release</h2>
          <p>
            Claude Code is the harness Lonca is built and checked against. Name it when you start a
            session and Lonca writes its MCP entry and hooks into the workspace; start{' '}
            <code>claude</code> there and every tool call goes through the gatekeeper.
          </p>
        </div>
        <div className="lonca-claude-grid">
          {claudeCode.map((c) => (
            <div className="lonca-claude-card" key={c.mark}>
              <code>{c.mark}</code>
              <h3>{c.title}</h3>
              <p>{c.text}</p>
            </div>
          ))}
        </div>
        <img
          className="lonca-figure"
          src={useBaseUrl('/img/claude-code-loop.svg')}
          alt="Claude Code's hook events and Lonca's MCP tools, each carried to the daemon by lonca hook or lonca mcp, with what the daemon does with them"
          width="1200"
          height="640"
          loading="lazy"
        />
        <CodeBlock language="bash">{claudeSetup}</CodeBlock>
        <div className="lonca-center">
          <Link className="button button--primary button--lg" to="/docs/guide/claude-code">
            Lonca with Claude Code
          </Link>
        </div>
      </div>
    </section>
  );
}

function Harnesses() {
  return (
    <section className="lonca-harnesses">
      <div className="container">
        <div className="lonca-section-head">
          <span className="lonca-eyebrow">Harnesses</span>
          <h2>Claude Code today, the others on the way</h2>
          <p>
            Lonca knows no harness in its code: each is a profile of data. Full support means its
            hooks can be shown to hold, so its sessions are trusted without a person approving every
            change. Every harness can already reach the highest level, <code>isolated</code>, inside{' '}
            <code>lonca run</code>.
          </p>
        </div>
        <div className="lonca-harness-grid">
          {harnesses.map((h) => (
            <div className={`lonca-harness lonca-harness--${h.tone}`} key={h.name}>
              <div className="lonca-harness-top">
                <h3>{h.name}</h3>
                <span className="lonca-badge">{h.status}</span>
              </div>
              <p>{h.text}</p>
            </div>
          ))}
        </div>
        <img
          className="lonca-figure"
          src={useBaseUrl('/img/observation-levels.svg')}
          alt="Observation levels from unobserved to isolated; Claude Code reaches all four, other harnesses unobserved with hooks and isolated under lonca run"
          width="1200"
          height="420"
          loading="lazy"
        />
      </div>
    </section>
  );
}

const claudeSetup = `lonca session start --repo demo --agent claude --paths 'src/**' \\
      --workspace ~/ws/claude-1 --harness claude-code
cd ~/ws/claude-1 && claude           # hooks and lonca mcp are already set up`;

export default function Home() {
  const { siteConfig } = useDocusaurusContext();
  const version = siteConfig.customFields.version;
  return (
    <Layout
      title="Agent-native, Git-compatible version control"
      description="Lonca is a version control system for repositories where many AI agents and a few humans work at the same time: one deterministic gatekeeper, narrow capabilities, symbol leases, a structural merge queue and a signed log anyone can replay.">
      <header className="lonca-hero">
        <img src={useBaseUrl('/img/lonca-mark.svg')} alt="" />
        <h1>Lonca</h1>
        <Link className="lonca-version" to="/docs/release-notes">
          <span className="lonca-version-dot" aria-hidden="true" />v{version} · latest release
        </Link>
        <div className="lonca-tagline">Agent-native, Git-compatible version control</div>
        <p>
          For repositories where many AI agents and a few humans work at the same time. Content
          stays plain Git; what changes is who may do what, how concurrent work merges, and how
          every action is recorded and checked.
        </p>
        <InstallLine />
        <div>
          <Link className="button button--primary button--lg" to="/docs/guide/quick-start">
            Quick start
          </Link>
          <Link className="button button--secondary button--lg" to="/docs/guide">
            What Lonca is
          </Link>
        </div>
        <div className="lonca-flow" aria-label="How a change reaches trunk">
          {flow.map((step, i) => (
            <React.Fragment key={step}>
              {i > 0 && <span className="arrow">→</span>}
              <span>{step}</span>
            </React.Fragment>
          ))}
        </div>
      </header>
      <main>
        <section className="lonca-features container">
          <div className="row">
            {features.map((f) => (
              <div className="col col--4" key={f.title}>
                <h3>{f.title}</h3>
                <p>{f.text}</p>
              </div>
            ))}
          </div>
        </section>
        <ClaudeCode />
        <Harnesses />
        <section className="lonca-terminal">
          <h2>A session, start to end</h2>
          <CodeBlock language="bash">{session}</CodeBlock>
        </section>
        <section className="lonca-other">
          <h2>Other ways to install</h2>
          <CodeBlock language="bash">{other}</CodeBlock>
          <p>
            Every release archive has checksums and a build provenance attestation (
            <code>gh attestation verify lonca-&lt;target&gt;.tar.gz --repo selcukgural/lonca</code>
            ). See <Link to="/docs/guide/install">Install</Link> for hardened mode.
          </p>
        </section>
      </main>
    </Layout>
  );
}

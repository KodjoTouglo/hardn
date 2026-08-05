//! Interactive ratatui front-end: a dashboard to inspect, apply, and uninstall
//! modules. Drives the same engine as the CLI. Long operations run in Tokio
//! tasks and stream results back to the UI over a channel.

#![forbid(unsafe_code)]

mod app;
mod ui;

use std::io::{self, Stdout};

use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use futures::StreamExt;
use gli_core::{Config, Context};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::mpsc::UnboundedSender;

use app::{Action, App, Msg, Row};

type Term = Terminal<CrosstermBackend<Stdout>>;

/// Render one dashboard frame to plain text with sample data, for docs and
/// screenshots. Colors are not represented.
pub fn preview(width: u16, height: u16) -> String {
    use gli_core::State;
    use ratatui::backend::TestBackend;
    use ratatui::layout::Position;

    let sample = |name: &str, summary: &str, state: State| Row {
        name: name.to_string(),
        summary: summary.to_string(),
        state,
        detail: String::new(),
    };
    let mut app = App {
        rows: vec![
            sample(
                "ssh",
                "Harden sshd: custom port, no root/password login",
                State::Compliant,
            ),
            sample(
                "firewall",
                "nftables default-deny, allow-list",
                State::Drift,
            ),
            sample(
                "users",
                "Create users, grant sudo, install SSH keys",
                State::Compliant,
            ),
            sample(
                "docker",
                "Install Docker, enable, add users to group",
                State::NotApplicable,
            ),
            sample("caddy", "Reverse proxy with automatic HTTPS", State::Drift),
        ],
        ..App::default()
    };
    app.marked.insert("firewall".to_string());
    app.push_log("scanning modules...");
    app.push_log("ssh: 3 change(s) applied");

    let mut term = Terminal::new(TestBackend::new(width, height)).unwrap();
    term.draw(|f| ui::draw(f, &app)).unwrap();

    let buf = term.backend().buffer();
    let mut out = String::new();
    for y in 0..height {
        for x in 0..width {
            if let Some(cell) = buf.cell(Position::new(x, y)) {
                out.push_str(cell.symbol());
            }
        }
        out.push('\n');
    }
    out
}

/// Run the dashboard against the local host until the operator quits.
pub async fn run(config: Config) -> io::Result<()> {
    let ctx = Context::system(config);
    let mut terminal = setup()?;
    let result = event_loop(&mut terminal, ctx).await;
    restore(&mut terminal)?;
    result
}

async fn event_loop(terminal: &mut Term, ctx: Context) -> io::Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut appstate = App::default();
    appstate.push_log("scanning modules...");
    spawn_scan(ctx.clone(), tx.clone());

    let mut events = EventStream::new();
    loop {
        terminal.draw(|f| ui::draw(f, &appstate))?;
        tokio::select! {
            msg = rx.recv() => {
                if let Some(msg) = msg {
                    handle_msg(&mut appstate, msg);
                }
            }
            ev = events.next() => {
                if let Some(Ok(Event::Key(key))) = ev {
                    if key.kind == KeyEventKind::Press {
                        handle_key(&mut appstate, key.code, &ctx, &tx);
                    }
                }
            }
        }
        if appstate.should_quit {
            return Ok(());
        }
    }
}

fn handle_msg(app: &mut App, msg: Msg) {
    match msg {
        Msg::Rows(rows) => {
            app.rows = rows;
            if app.selected >= app.rows.len() {
                app.selected = app.rows.len().saturating_sub(1);
            }
        }
        Msg::Log(line) => app.push_log(line),
        Msg::Busy(b) => app.busy = b,
    }
}

fn handle_key(app: &mut App, code: KeyCode, ctx: &Context, tx: &UnboundedSender<Msg>) {
    // Confirmation dialog intercepts keys first.
    if let Some(action) = app.confirm {
        match code {
            KeyCode::Char('y') => {
                let targets = app.targets();
                app.confirm = None;
                match action {
                    Action::Apply => spawn_apply(ctx.clone(), tx.clone(), targets),
                    Action::Uninstall => spawn_uninstall(ctx.clone(), tx.clone(), targets),
                }
            }
            KeyCode::Char('n') | KeyCode::Esc => app.confirm = None,
            _ => {}
        }
        return;
    }

    match code {
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
        KeyCode::Down | KeyCode::Char('j') => app.next(),
        KeyCode::Up | KeyCode::Char('k') => app.prev(),
        KeyCode::Char(' ') => app.toggle_mark(),
        KeyCode::Char('r') if !app.busy => spawn_scan(ctx.clone(), tx.clone()),
        KeyCode::Char('p') | KeyCode::Enter if !app.busy => {
            if let Some(row) = app.current() {
                spawn_plan(ctx.clone(), tx.clone(), row.name.clone());
            }
        }
        KeyCode::Char('a') if !app.busy => app.confirm = Some(Action::Apply),
        KeyCode::Char('u') if !app.busy => app.confirm = Some(Action::Uninstall),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Background workers
// ---------------------------------------------------------------------------

fn spawn_scan(ctx: Context, tx: UnboundedSender<Msg>) {
    tokio::spawn(async move {
        let catalog = gli_modules::catalog();
        let mut rows = Vec::new();
        for module in catalog.iter() {
            let status = module.check(&ctx).await;
            let (state, detail) = match status {
                Ok(s) => (s.state, s.detail),
                Err(e) => (gli_core::State::Error, e.to_string()),
            };
            rows.push(Row {
                name: module.name().to_string(),
                summary: module.summary().to_string(),
                state,
                detail,
            });
        }
        let _ = tx.send(Msg::Rows(rows));
    });
}

fn spawn_plan(ctx: Context, tx: UnboundedSender<Msg>, name: String) {
    tokio::spawn(async move {
        let catalog = gli_modules::catalog();
        let Some(module) = catalog.get(&name) else {
            return;
        };
        let _ = tx.send(Msg::Log(format!("=== plan: {name} ===")));
        match module.plan(&ctx).await {
            Ok(changes) if changes.is_empty() => {
                let _ = tx.send(Msg::Log(format!("{name}: no changes")));
            }
            Ok(changes) => {
                for c in changes {
                    let _ = tx.send(Msg::Log(format!("  {}", c.summary)));
                }
            }
            Err(e) => {
                let _ = tx.send(Msg::Log(format!("{name}: error: {e}")));
            }
        }
    });
}

fn spawn_apply(ctx: Context, tx: UnboundedSender<Msg>, targets: Vec<String>) {
    tokio::spawn(async move {
        let _ = tx.send(Msg::Busy(true));
        let catalog = gli_modules::catalog();
        for name in targets {
            let Some(module) = catalog.get(&name) else {
                continue;
            };
            match module.apply(&ctx, false).await {
                Ok(report) if report.is_noop() => {
                    let _ = tx.send(Msg::Log(format!("{name}: nothing to do")));
                }
                Ok(report) => {
                    let _ = tx.send(Msg::Log(format!(
                        "{name}: {} change(s) applied",
                        report.applied.len()
                    )));
                }
                Err(e) => {
                    let _ = tx.send(Msg::Log(format!("{name}: error: {e}")));
                }
            }
        }
        let _ = tx.send(Msg::Busy(false));
        spawn_scan(ctx, tx);
    });
}

fn spawn_uninstall(ctx: Context, tx: UnboundedSender<Msg>, targets: Vec<String>) {
    tokio::spawn(async move {
        let _ = tx.send(Msg::Busy(true));
        let catalog = gli_modules::catalog();
        // Provisioning first, security baseline last.
        for name in targets.into_iter().rev() {
            let Some(module) = catalog.get(&name) else {
                continue;
            };
            match module.uninstall(&ctx, false).await {
                Ok(report) => {
                    let _ = tx.send(Msg::Log(format!(
                        "{name}: uninstalled ({} step(s))",
                        report.applied.len()
                    )));
                }
                Err(e) => {
                    let _ = tx.send(Msg::Log(format!("{name}: error: {e}")));
                }
            }
        }
        let _ = tx.send(Msg::Busy(false));
        spawn_scan(ctx, tx);
    });
}

// ---------------------------------------------------------------------------
// Terminal lifecycle
// ---------------------------------------------------------------------------

fn setup() -> io::Result<Term> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    Terminal::new(CrosstermBackend::new(stdout))
}

fn restore(terminal: &mut Term) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()
}

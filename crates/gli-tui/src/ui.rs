//! Rendering of the dashboard, separate from state.

use gli_core::State;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph};
use ratatui::Frame;

use crate::app::{Action, App};

pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),
            Constraint::Min(6),
            Constraint::Length(8),
            Constraint::Length(1),
        ])
        .split(f.area());

    header(f, app, chunks[0]);
    modules(f, app, chunks[1]);
    log(f, app, chunks[2]);
    help(f, chunks[3]);

    if let Some(action) = app.confirm {
        confirm_popup(f, action, &app.targets());
    }
}

fn header(f: &mut Frame, app: &App, area: Rect) {
    let (ok, total) = app.score();
    let pct = (ok * 100).checked_div(total).unwrap_or(0);
    let busy = if app.busy { "  working..." } else { "" };
    let title = format!(" gli   security {pct}% ({ok}/{total} compliant){busy} ");
    let p = Paragraph::new(gli_core::BANNER)
        .style(Style::default().fg(Color::Cyan))
        .block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(p, area);
}

fn modules(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let mark = if app.marked.contains(&r.name) {
                "[x]"
            } else {
                "[ ]"
            };
            let (glyph, color) = state_style(r.state);
            let cursor = if i == app.selected { ">" } else { " " };
            let line = Line::from(vec![
                Span::raw(format!("{cursor} {mark} ")),
                Span::styled(format!("{glyph} "), Style::default().fg(color)),
                Span::styled(format!("{:<10}", r.name), Style::default().fg(color)),
                Span::raw(format!(" {}", r.summary)),
            ]);
            ListItem::new(line)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title("modules (space: select, p: plan, a: apply, u: uninstall)"),
    );
    f.render_widget(list, area);
}

fn log(f: &mut Frame, app: &App, area: Rect) {
    let height = area.height.saturating_sub(2) as usize;
    let start = app.log.len().saturating_sub(height);
    let lines: Vec<Line> = app.log[start..]
        .iter()
        .map(|l| Line::raw(l.clone()))
        .collect();
    let p = Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title("output"));
    f.render_widget(p, area);
}

fn help(f: &mut Frame, area: Rect) {
    let text = " j/k move  space select  p plan  a apply  u uninstall  r refresh  q quit";
    f.render_widget(
        Paragraph::new(text).style(Style::default().fg(Color::DarkGray)),
        area,
    );
}

fn confirm_popup(f: &mut Frame, action: Action, targets: &[String]) {
    let verb = match action {
        Action::Apply => "Apply",
        Action::Uninstall => "Uninstall",
    };
    let area = centered(60, 30, f.area());
    f.render_widget(Clear, area);
    let body = format!(
        "{verb} {} module(s):\n{}\n\ny: confirm    n/Esc: cancel",
        targets.len(),
        targets.join(", ")
    );
    let p = Paragraph::new(body).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Confirm {verb}"))
            .style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
    );
    f.render_widget(p, area);
}

fn state_style(state: State) -> (&'static str, Color) {
    match state {
        State::Compliant => ("ok", Color::Green),
        State::Drift => ("~", Color::Yellow),
        State::Error => ("x", Color::Red),
        State::NotApplicable => ("-", Color::DarkGray),
    }
}

fn centered(pct_x: u16, pct_y: u16, area: Rect) -> Rect {
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - pct_y) / 2),
            Constraint::Percentage(pct_y),
            Constraint::Percentage((100 - pct_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - pct_x) / 2),
            Constraint::Percentage(pct_x),
            Constraint::Percentage((100 - pct_x) / 2),
        ])
        .split(v[1])[1]
}

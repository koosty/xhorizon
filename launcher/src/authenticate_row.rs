//! Settings' Authenticate With rows (`authenticate::Authenticate`): which service signs the
//! player in, and under Custom URL the address it uses. Read at each Play, so a change applies
//! the next time the player plays.
use super::*;
use horizon_launcher::account::{horizon_account_host, warn_about_address, Authenticate};

impl Launcher {
    /// The choice of service, as a segmented picker.
    pub(super) fn authenticate_row(&self, n: usize, cx: &mut Context<Self>) -> Div {
        let t = self.theme;
        let options = vec![
            (Authenticate::Mojang, "Mojang"),
            (Authenticate::HorizonAccount, "Horizon Account Provider"),
        ];
        let current = self.settings.authenticate_with;
        let picker = segments("authenticate-with", &options, current, &t, {
            let this = cx.entity().downgrade();
            move |choice, _, cx| {
                let _ = this.update(cx, |this, cx| {
                    this.settings.authenticate_with = choice;
                    // The accounts of the new service play; the others stay listed, unused.
                    let mut accounts = Accounts::load();
                    accounts.follow(choice);
                    if let Err(e) = accounts.save() {
                        eprintln!("Horizon: the accounts are not saved: {e}");
                    }
                    this.accounts = accounts.clone();
                    this.save_settings();
                    // Who may play changed: the owner state follows, off this thread (the keychain can block).
                    let tx = this.tx.clone();
                    std::thread::spawn(move || {
                        let _ = tx.send(Msg::Owner(accounts.can_play(account::store())));
                    });
                    cx.notify();
                });
            }
        });
        let said = match current {
            Authenticate::Mojang => {
                "Signs in with a Microsoft account that owns Minecraft: Java Edition."
            }
            Authenticate::HorizonAccount => {
                "Signs in through the custom auth service below. Applies the next time you play."
            }
        };
        index_row(
            n,
            tr("Authenticate With"),
            Some(div().child(tr(said)).into_any_element()),
            Some(picker.into_any_element()),
            &t,
        )
    }

    /// Under Custom URL: the service's address, the host it will use, and the warning that
    /// asks the player to trust an address they have not used before. Empty otherwise.
    pub(super) fn custom_url_row(&self, n: usize, cx: &mut Context<Self>) -> Div {
        let t = self.theme;
        if self.settings.authenticate_with != Authenticate::HorizonAccount {
            return div();
        }
        let focused = self.custom_url_focused;
        let field = div()
            .id("custom-auth-url")
            .track_focus(&self.custom_url_focus)
            .flex()
            .items_center()
            .w(px(300.))
            .h(px(30.))
            .px(px(12.))
            .overflow_hidden()
            .border_2()
            .border_color(if focused { t.accent } else { t.outline })
            .bg(t.well)
            .font_family(theme::MONO)
            .text_size(px(12.))
            .cursor_text()
            .child(line_edit::content(
                &self.custom_url_input,
                &t,
                focused,
                false,
                false,
                tr("https://auth.example.org"),
            ))
            .on_click(cx.listener(|this, _: &ClickEvent, window, cx| {
                window.focus(&this.custom_url_focus, cx);
                cx.notify();
            }))
            .on_key_down(cx.listener(|this, ev: &KeyDownEvent, window, cx| {
                match line_edit::handle(&mut this.custom_url_input, ev, cx) {
                    line_edit::Key::Pass => return,
                    line_edit::Key::Escape => window.blur(cx),
                    line_edit::Key::Edited => this.save_custom_url(),
                    _ => {}
                }
                cx.stop_propagation();
                cx.notify();
            }));
        let field = line_edit::mouse(field, cx, |this| &mut this.custom_url_input);
        let typed = self.custom_url_input.text().trim().to_owned();
        let saved = self.settings.horizon_account_url.as_deref();
        let mut detail = div();
        // A half-typed address is no reason to complain; one left behind is.
        match (focused, horizon_account_host(&typed)) {
            (false, Err(why)) if !typed.is_empty() => {
                detail = detail.text_color(t.danger).child(tr(why));
            }
            (_, Ok(host)) => {
                detail = detail.child(trf(
                    "The launcher signs in through {host}.",
                    &[("host", &host)],
                ));
            }
            _ => {
                detail = detail.child(tr("The address of the custom auth service, over https://."));
            }
        }
        if !focused
            && warn_about_address(
                Authenticate::HorizonAccount,
                saved,
                self.settings.horizon_account_trusted.as_deref(),
            )
        {
            let this = cx.entity().downgrade();
            let trust = button(
                "trust-custom-auth",
                tr("Trust this address"),
                Kind::Secondary,
                &t,
            )
            .on_click(move |_, _, cx| {
                let _ = this.update(cx, |this, cx| {
                    this.settings.horizon_account_trusted = this.settings.horizon_account_url.clone();
                    this.save_settings();
                    cx.notify();
                });
            });
            detail = detail
                .child(div().text_color(t.danger).child(tr(
                    "This address is new. Check it is your service before you play.",
                )))
                .child(trust);
        }
        index_row(
            n,
            tr("Horizon Account Provider URL"),
            Some(detail.into_any_element()),
            Some(field.into_any_element()),
            &t,
        )
    }

    /// Keeps the typed address once it passes [`horizon_account_host`]. A refused one stays in the field
    /// with its reason, and the last good address stays saved.
    fn save_custom_url(&mut self) {
        let value = self.custom_url_input.text().trim().to_owned();
        if value.is_empty() {
            self.settings.horizon_account_url = None;
        } else if horizon_account_host(&value).is_ok() {
            self.settings.horizon_account_url = Some(value);
        } else {
            return;
        }
        self.save_settings();
    }
}

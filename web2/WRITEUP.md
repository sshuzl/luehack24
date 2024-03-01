# CTF-Herausforderung web2

## Überblick

In dieser Herausforderung werden die Teilnehmer aufgefordert, sich an einem Web-Interface anzumelden, um Zugang zu einer geheimen "Flagge" (einem geheimen Code) zu erhalten. Die Herausforderung besteht darin, den richtigen Benutzernamen und das Passwort zu finden, um sich erfolgreich anzumelden.

## Schritt 1: Untersuchung der Anmeldeseite

Besuche die Anmeldeseite der Herausforderung. Du wirst ein einfaches Anmeldeformular mit Feldern für Benutzername und Passwort sehen.

## Schritt 2: Inspektion des Quellcodes

Der erste und wichtigste Schritt bei vielen CTF-Herausforderungen ist die Inspektion des Quellcodes der Webseite. In den meisten Webbrowsern kannst du mit der rechten Maustaste auf die Seite klicken und "Seitenquelltext anzeigen" oder "Element untersuchen" wählen.

## Schritt 3: Finden der versteckten Hinweise

Im Quellcode findest du zwei versteckte HTML-Elemente mit den IDs `developer-username` und `developer-password`. Diese Elemente enthalten die benötigten Anmeldeinformationen:

- Benutzername: `Adm1n`
- Passwort: `P4ssw0rd!`

Diese Hinweise sind im Quelltext mit `display:none;` versteckt, sodass sie auf der Webseite nicht direkt sichtbar sind.

## Schritt 4: Anmeldung

Gehe zurück zum Anmeldeformular auf der Webseite und verwende die gefundenen Anmeldeinformationen, um dich anzumelden:

- Benutzername: `Adm1n`
- Passwort: `P4ssw0rd!`

## Schritt 5: Zugang zur Flagge

Nach erfolgreicher Anmeldung wirst du zur "Erfolgsseite" weitergeleitet, auf der die Flagge direkt angezeigt wird. Notiere dir die Flagge, denn sie ist der Beweis dafür, dass du die Herausforderung erfolgreich gemeistert hast.

## Fazit

Diese Herausforderung lehrt die grundlegende Fähigkeit, den Quellcode von Webseiten zu untersuchen und versteckte Informationen zu finden. Solche Fähigkeiten sind in der Welt der Informationssicherheit und beim ethischen Hacking sehr wertvoll. Es ist wichtig zu lernen, wie man solche Informationen auf verantwortungsvolle Weise nutzt und die Privatsphäre und Sicherheit anderer respektiert.

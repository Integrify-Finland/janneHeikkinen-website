import React from "react"

import { storiesOf } from "@storybook/react"
import { jsxDecorator } from "storybook-addon-jsx"

import Header from ".."

storiesOf("Header", module)
  .addDecorator(jsxDecorator)
  .add("Etusivu Header", () => <Header Subtext="Kansanedustaja, yhteiskuntatieteiden maisteri ja intohimoinen perhokalastaja."/>)

  .add("About Header", () => <Header isAbout={true} Kotipaikka="Heinäpää, Oulu" Syntynyt="1990 Oulussa" Perhe="Avovaimo Mira sekä äiti Sirpa, isä Kari, sisko Sanni ja veli Matti sekä pohjanpystykorva Sissi." Sotilasarvo_aselinja="jääkäri, sissi" Ammatti="Viestinnän suunnittelija" Harrastukset="Salibandy, sulkapallo, kalastus, tennis" Koulutus="Yhteiskuntatieteiden maisteri Jyväskylän yliopistosta" Luottamustehtava="Kansanedustaja, kaupunginvaltuutettu"/>)




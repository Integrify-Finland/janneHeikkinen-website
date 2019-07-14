import React, { useState } from "react"

import { storiesOf } from "@storybook/react"
import { jsxDecorator } from "storybook-addon-jsx"

import Resume from ".."

const opinnot = [
  "Yleinen valtio-oppi, Yhteiskuntatieteellinen tiedekunta, Jyväskylän Yliopisto 2012-2018",
  "Politiikan Approbatur 2011",
  "Kempeleen lukio, Ylioppilas 2009",
]
const varusmiespalvelus = [
  "Jääkäri, Sissikomppania, Sodankylän Jääkäriprikaati 2009",
]
const tyoelamassa = [
  "Viestinnän suunnittelija, Elinkeinoelämän valtuuskunta EVA 2016-2018",
  "Yrittäjä, Salibandykauppa Avoin Yhtiö 2009-2010",
  "Myymälätyöntekijä, Osuuskauppa Arina 2008-2012 ",
  "Jäätelönmyyjä, Valio 2005-2006",
  "Salibandyvalmentaja, Kempeleen Kiri, Merikoski SBT 2006-2012",
]
const luottamustoimet = [
  "Kansanedustaja 2019-",
  "Oulun kaupunginvaltuutettu 2017-",
  "Oulun kaupunginhallituksen jäsen 2017-",
  "BusinessOulun johtokunnan varapuheenjohtaja 2017-",
  "Pohjois-Pohjanmaan Maakuntavaltuutettu 2017-",
  "Suomen Kuntaliiton valtuuskunnan jäsen 2018-",
  "Kempeleen kunnanvaltuuston puheenjohtaja 2015-2016",
  "Kempeleen kunnanvaltuutettu 2009-2016",
  "Kempeleen kunnanhallituksen varapuheenjohtaja 2013-2014",
  "Kempeleen palveluvaliokunnan jäsen 2009-2012",
  "Kempeleen kunnanhallituksen jaoston jäsen 2009-2012",
  "Kokoomuksen Nuorten Liiton liittohallituksen jäsen 2013",
  "Oulun Läänin Kokoomusnuoret ry puheenjohtaja 2012-2013",
  "Oulun Läänin Kokoomusnuoret ry piirihallituksen jäsen 2010-2014",
  "Pohjois-Pohjanmaan Kokoomuksen piirihallituksen jäsen 2012",
  "Pohjois-Pohjanmaan Kokoomuksen varapuheenjohtaja 2016",
  "Kempeleen Kirin hallituksen jäsen 2008",
  "Oulun Seudun Perhokalastajat ry hallituksen jäsen 2011-2012, 2017- ",
  "Suomen Pokerinpelaajat ry hallituksen jäsen 2014 –",
]
storiesOf("Resume", module)
  .addDecorator(jsxDecorator)
  .add("with props", () => (
    <div style={{ marginTop: "4rem" }}>
      <Resume
        opinnot={opinnot}
        varusmies={varusmiespalvelus}
        tyo={tyoelamassa}
        luottamus={luottamustoimet}
      />
    </div>
  ))

import React from "react"

import { storiesOf } from "@storybook/react"
import { jsxDecorator } from "storybook-addon-jsx"

import Header from ".."

storiesOf("Header", module)
  .addDecorator(jsxDecorator)
  .add("with siteTitle", () => <Header Subtext="Kansanedustaja, yhteiskuntatieteiden maisteri ja intohimoinen perhokalastaja."/>)

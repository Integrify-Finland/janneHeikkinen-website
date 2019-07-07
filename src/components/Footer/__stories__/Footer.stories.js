import React from "react"
import { storiesOf } from "@storybook/react"
import { jsxDecorator } from "storybook-addon-jsx"

import Footer from ".."
storiesOf("Footer", module)
  .addDecorator(jsxDecorator)
  .add("Footer", () => <Footer  firstPersonName="Janne&nbsp;Heikkinen" firstPersonTitle="Kansanedustaja" firstPersonPhone="+358 (0) 40 5554263" firstPersonEmail="janne.heikkinen (at) eduskunta.fi" secondPersonName="Mikko&nbsp;Laakso"secondPersonTitle="Kansanedustajan avustaja" secondPersonPhone="+358 (0) 50 383 9432" secondPersonEmail="mikko.laakso (at) eduskunta.fi"/>)

  

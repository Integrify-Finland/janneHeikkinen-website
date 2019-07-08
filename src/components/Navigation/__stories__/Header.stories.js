import React from "react"

import { storiesOf } from "@storybook/react"
import { jsxDecorator } from "storybook-addon-jsx"

import Navigation from ".."

storiesOf("Navigation", module)
  .addDecorator(jsxDecorator)
  .add("without props", () => <Navigation />)

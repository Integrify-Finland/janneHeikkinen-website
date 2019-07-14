import React from "react"

import { storiesOf } from "@storybook/react"
import { jsxDecorator } from "storybook-addon-jsx"

import Navbar from ".."

storiesOf("Navigation", module)
  .addDecorator(jsxDecorator)
  .add("Navbar", () => <Navbar />)
  .add('mobile', () => <Navbar />, {
    viewport: 'iphone8p',
  })

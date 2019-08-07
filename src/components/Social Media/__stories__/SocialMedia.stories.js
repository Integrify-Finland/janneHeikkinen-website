import React from "react"
import { storiesOf } from "@storybook/react"
import { jsxDecorator } from "storybook-addon-jsx"

import SocialMedia from ".."
storiesOf("SocialMedia", module)
  .addDecorator(jsxDecorator)
  .add("SocialMedia", () => (
    <SocialMedia />
  ))

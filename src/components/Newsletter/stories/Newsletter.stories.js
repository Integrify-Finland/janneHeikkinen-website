import React from "react"

import { storiesOf } from "@storybook/react"
import { jsxDecorator } from "storybook-addon-jsx"

import Newsletter from ".."

const styles = {
  display: "flex",
  justifyContent: "center",
  alignItems: "center",
  height: "100vh",
}
storiesOf("Newsletter", module)
  .addDecorator(jsxDecorator)
  .add("newsletter", () => (
    <div style={styles}>
      <Newsletter />
    </div>
  ))

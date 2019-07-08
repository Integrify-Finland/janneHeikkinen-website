import React from "react"

import { storiesOf } from "@storybook/react"
import { jsxDecorator } from "storybook-addon-jsx"

import Newsletter from ".."
storiesOf("Newsletter", module)
    .addDecorator(jsxDecorator)
    .add("newsletter", () => 
    <Newsletter />
    )

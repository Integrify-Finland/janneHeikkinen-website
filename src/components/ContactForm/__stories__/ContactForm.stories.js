import React from "react"

import { storiesOf } from "@storybook/react"
import { jsxDecorator } from "storybook-addon-jsx"

import ContactForm from ".."

const styles = {
    display: "flex",
    justifyContent: "center",
    alignItems: "flex-start",
    height: "100vh",
    backgroundColor: "#EDF5F8",
    paddingTop: "20px"
}

storiesOf("ContactForm", module)
    .addDecorator(jsxDecorator)
    .add("Form", () => (
        <div style={styles}>
            <ContactForm />
        </div>
    ))
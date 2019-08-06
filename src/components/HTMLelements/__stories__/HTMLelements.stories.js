import React from "react"
import { storiesOf } from "@storybook/react"
import { jsxDecorator } from "storybook-addon-jsx"

import {
  Bold,
  Italic,
  Underline,
  H1,
  H2,
  H3,
  H4,
  H5,
  H6,
  OlLists,
  Paragraph,
  UlLists,
  QUOTE,
  HR,
  HYPERLINK,
  Image,
} from ".."

const styles = {
  display: "flex",
  "flex-direction": "column",
  "margin-bottom": "2rem",
}

storiesOf("Blog Post elements", module)
  .addDecorator(jsxDecorator)
  .add("Single Elements", () => (
    <>
      <section style={styles}>
        <strong>Bold text</strong>
        <Bold> some text </Bold>
      </section>

      <section style={styles}>
        <strong>Italic text</strong>
        <Italic> some text </Italic>
      </section>

      <section style={styles}>
        <strong>Underline text</strong>
        <Underline> some text </Underline>
      </section>

      <section style={styles}>
        <strong>Header 1</strong>
        <H1> some text </H1>
      </section>

      <section style={styles}>
        <strong>Header 2</strong>
        <H2> some text </H2>
      </section>

      <section style={styles}>
        <strong>Header 3</strong>
        <H3> some text </H3>
      </section>

      <section style={styles}>
        <strong>Header 4</strong>
        <H4> some text </H4>
      </section>

      <section style={styles}>
        <strong>Header 5</strong>
        <H5> some text </H5>
      </section>

      <section style={styles}>
        <strong>Header 6</strong>
        <H6> some text </H6>
      </section>

      <section style={styles}>
        <OlLists>
          <ol>
            <li>list 1</li>
            <li>list 2</li>
          </ol>
        </OlLists>
      </section>

      <section style={styles}>
        <UlLists>
          <ul>
            <li>list 1</li>
            <li>list 2</li>
          </ul>
        </UlLists>
      </section>

      <section style={styles}>
        <Paragraph> some text </Paragraph>
      </section>

      <section style={styles}>
        <QUOTE> some text </QUOTE>
      </section>

      <section style={styles}>
        <HR> some text </HR>
      </section>

      <section style={styles}>
        <HYPERLINK> some text </HYPERLINK>
      </section>

      <section style={styles}>
        <Image url="url-here"> some text </Image>
      </section>
    </>
  ))

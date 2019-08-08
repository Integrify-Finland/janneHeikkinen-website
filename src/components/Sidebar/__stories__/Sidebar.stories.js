import React from "react"

import { storiesOf } from "@storybook/react"
import { jsxDecorator } from "storybook-addon-jsx"

import Sidebar from ".."

import image from "../../../images/JANNE_HEIKKINEN_260619_77.jpg"

const styles = {
  display: "flex",
  justifyContent: "center",
  alignItems: "flex-start",
  height: "100vh",
  backgroundColor: "#EDF5F8",
  paddingTop: "20px",
}

const text =
  "Julkaistu alun perin Kalevassa 5.6.2019 Minun ei käy kateeksi näinä päivinä suomalaista pienyrittäjää. Heidän äänensä ei ole liiemmin kuulunut viime viikkoina säätytalolla. Sen sijaan tulevan hallituksen ohjelmaa ovat olleet kunniavieraina kirjoittamassa kansainvälisten suuryritysten ja etujärjestöjen palkkaamat lobbaustoimistot. Ikävä kyllä pienyrittäjillä ei ole vastaavaa taloudellista mahdollisuutta kalliisiin"
const shortText = text.substr(0, 416) + "..."

const blogs = {
  edges: [
    {
      node: {
        id: "df4e1996-b2c5-52b5-8feb-3cdd142f2884",
        slug: "blog-post-1",
        tags: ["Espoo", "Business"],
        title: "Blog Number 1",
      },
    },
    {
      node: {
        id: "4464ed05-c35d-53e2-8233-824ba210615e",
        slug: "blog-post-2",
        tags: ["Espoo", "Helsinki"],
        title: "Blog Number 2",
      },
    },
  ],
}
const tags = ["Espoo", "Helsinki", "Business"]

const categories = ["Politics", "Forest", "Nature"]
storiesOf("Sidebar", module)
  .addDecorator(jsxDecorator)
  .add("default", () => (
    <div>
      <Sidebar
        blogs={blogs.edges}
        image={image}
        shortText={shortText}
        categories={categories}
        tags={tags}
      />
    </div>
  ))

import React from "react"
import { graphql } from "gatsby"

import Layout from "../components/Layout"
import Image from "../components/Image"
import SEO from "../components/SEO"
import Media from "../components/Media"
import Section from "../components/Section"

const Medialle = ({ data }) => {
  const { forMedia } = data

  return (
    <Layout>
      <SEO title="Medialle" />
      <Section>
        <Media />
        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            justifyContent: "space-between",
          }}
        >
          {forMedia.pictures.map((data, i) => (
            <a
              target="_blank"
              rel="noopener noreferrer"
              href={`https://${data.fluid.src}`}
            >
              <Image fluid={data.fluid} key={i} />
            </a>
          ))}
        </div>
        <p style={{ textAlign: "center", fontWeight: "400", color: "#023b56" }}>
          Oheisia kuvia saa käyttää vapaasti median julkaisuissa.
        </p>
      </Section>
    </Layout>
  )
}

export default Medialle

export const query = graphql`
  query {
    forMedia: contentfulForTheMedia {
      description {
        id
        description
      }
      pictures {
        fluid(maxWidth: 3200, quality: 100) {
          base64
          aspectRatio
          src
          srcSet
          srcWebp
          srcSetWebp
          sizes
        }
      }
    }
  }
`

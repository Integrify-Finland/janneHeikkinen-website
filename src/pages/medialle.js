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
          <Image fluid={data.fluid} key={i} />
        ))}
      </div>
          <p style= {{textAlign:"center", fontWeight:"bold", color:"$primary"}}>Oheisia kuvia saa käyttää vapaasti median julkaisuissa.</p>
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

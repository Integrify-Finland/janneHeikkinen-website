import React from "react"
import Img from "gatsby-image"
import { graphql } from "gatsby"

import Layout from "../../components/Layout"
import SEO from "../../components/SEO"
import Media from "../../components/Media"
import Section from "../../components/Section"
import "./styles.scss"
const Vaalit = ({ data }) => {
  const { vaalit } = data
  console.log(vaalit)
  return (
    <Layout>
      <SEO title="Medialle" />
      <Section>
        <div
          className="vaalit"
          dangerouslySetInnerHTML={{
            __html: vaalit.description.childMarkdownRemark.html,
          }}
        />
      </Section>
    </Layout>
  )
}

export default Vaalit

export const query = graphql`
  query {
    vaalit: contentfulKuntavaalit {
      description {
        childMarkdownRemark {
          id
          html
        }
      }
    }
  }
`

// <Img
//   fluid={forMedia?.pictures[0].fluid}
//   style={{
//     maxWidth: `95%`,
//     width: "750px",
//     margin: "20px auto",
//     border: "#6ccff6 2px solid",
//   }}
// />
// <Media text={forMedia.description.description} />
// <p style={{ textAlign: "center", fontWeight: "400", color: "#023b56" }}>
//   Oheisia kuvia saa käyttää vapaasti median julkaisuissa.
// </p>

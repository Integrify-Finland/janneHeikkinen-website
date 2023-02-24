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

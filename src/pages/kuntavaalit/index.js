import React from "react"
import { graphql } from "gatsby"
import Img from "gatsby-image"

import Layout from "../../components/Layout"
import SEO from "../../components/SEO"
import Section from "../../components/Section"

import "./styles.scss"

const Kuntavaalit = ({ data }) => {
  const { contentfulCandidate } = data

  const handleSplitTitle = str => {
    const hasBreak = str.includes("<br>")
    if (hasBreak) {
      return str.split("<br>")
    }
    return str.split("<br>")
  }

  const paragraphs = handleSplitTitle(
    contentfulCandidate.description.description
  )

  return (
    <Layout>
      <SEO title="Kuntavaalit" />
      <Section className="kuntavaalit">
        <div className=""></div>
        <div className="kuntavaalit__image">
          <a
            target="_blank"
            rel="noopener noreferrer"
            href={`https://${contentfulCandidate.image.fluid.src}`}
          >
            <Img
              fluid={contentfulCandidate.image.fluid}
              style={{ width: "80%", margin: "0 auto" }}
            />
          </a>
        </div>
        <div className="kuntavaalit__text">
          {paragraphs.map(p => (
            <p>{p}</p>
          ))}
        </div>
      </Section>
    </Layout>
  )
}

export default Kuntavaalit

export const query = graphql`
  query {
    contentfulCandidate {
      id
      description {
        description
      }
      image {
        fluid(quality: 100) {
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

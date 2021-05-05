import React from "react"
import { graphql } from "gatsby"
import Img from "gatsby-image"

import Layout from "../../components/Layout"
import SEO from "../../components/SEO"
import Section from "../../components/Section"

import "./styles.scss"

const Kuntavaalit = ({ data }) => {
  const { contentfulCandidate } = data

  function createMarkup() {
    return {
      __html: contentfulCandidate.description.childMarkdownRemark.html,
    }
  }

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
        <div
          dangerouslySetInnerHTML={createMarkup()}
          className="kuntavaalit-markup"
        />
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
        childMarkdownRemark {
          html
        }
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

import React from "react"
import { graphql } from "gatsby"

import Layout from "../components/Layout"
import Image from "../components/Image"
import SEO from "../components/SEO"

const IndexPage = ({ data }) => {
  const { aboutMe, wordPressBlogs, youTubeVid } = data
  console.log(wordPressBlogs.edges)
  console.log(youTubeVid.edges)
  return (
    <Layout>
      <SEO title="Home" />
      <h1>{aboutMe.title}</h1>
      <p>{aboutMe.description}</p>
      <div style={{ maxWidth: `300px`, marginTop: `10rem` }}>
        <Image />
      </div>
    </Layout>
  )
}

export default IndexPage

export const query = graphql`
  query {
    aboutMe: contentfulAboutMe {
      id
      title
      description
    }
    youTubeVid: allYoutubeVideo {
      edges {
        node {
          id
          title
          description
          videoId
          publishedAt
          privacyStatus
          channelTitle
        }
      }
    }
    wordPressBlogs: allWordpressPost {
      edges {
        node {
          id
          title
          tags {
            name
          }
        }
      }
    }
  }
`

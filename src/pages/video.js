import React from "react"
import { graphql } from "gatsby"

import Layout from "../components/Layout"
import SEO from "../components/SEO"

const Video = ({ data }) => {
  //   const { youTubeVid } = data

  return (
    <Layout>
      <SEO title="Videos" />
    </Layout>
  )
}

export default Video

export const query = graphql`
  query {
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
  }
`

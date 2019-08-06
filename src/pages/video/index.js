import React, { useState } from "react"
import { graphql } from "gatsby"

import Layout from "../../components/Layout"
import SEO from "../../components/SEO"
import Section from "../../components/Section"

import formateDate from "../../helpers/formateDate"

import "./styles.scss"

const Video = ({ data }) => {
  const { youTubeVid } = data
  const [vids, setVids] = useState(youTubeVid)

  const handlePlayVid = index => {
    const pop = vids.edges.filter((vid, i) => i === index)
    const filtered = vids.edges.filter((vid, i) => i !== index)
    const combined = { edges: [...pop, ...filtered] }
    setVids(combined)
    window.scrollTo(0, 0)
  }

  const renderActiveVideo = () => {
    return vids.edges.map(({ node }, index) => {
      return (
        <React.Fragment key={node.title}>
          {index === 0 && (
            <div className="youtube__player--active" key={node.title}>
              <iframe
                title={node.title}
                src={`https://www.youtube.com/embed/${node.videoId}`}
                frameBorder="0"
                allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture"
                allowFullScreen
              />
            </div>
          )}
        </React.Fragment>
      )
    })
  }
  const renderVideoLists = () => {
    return vids.edges.map(({ node }, index) => {
      return (
        <React.Fragment key={node.title}>
          {index !== 0 && (
            <div className="youtube__player">
              <div className="wrapper--overlay">
                <iframe
                  title={node.title}
                  src={`https://www.youtube.com/embed/${node.videoId}?feature=oembed&showinfo=0`}
                  frameBorder="0"
                  allowFullScreen
                />
                <div
                  className="youtube__player--overlay"
                  tabIndex="0"
                  role="button"
                  onClick={() => handlePlayVid(index)}
                  onKeyPress={() => {}}
                />
              </div>
              <strong>{node.title}</strong>

              <span
                style={{
                  color: "#707070",
                  marginTop: "0.5rem",
                  display: "block",
                }}
              >
                {formateDate(node.publishedAt, "long")}
              </span>
            </div>
          )}
        </React.Fragment>
      )
    })
  }
  return (
    <Layout>
      <SEO title="Videos" />

      <Section>
        <div className="youtube">
          {renderActiveVideo()}
          <div className="youtube-lists">{renderVideoLists()}</div>
        </div>
      </Section>
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

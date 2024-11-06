use std::io::Write;

    pub fn encode_candidate_cell(entries: &[Candidate]) -> Vec<u8> {
        let mut buf = Vec::<u8>::new();
        buf.write_all(&(entries.len() as u16).to_le_bytes())
            .unwrap();
        for item in entries.iter() {
            buf.write_all(&item.id).unwrap();
            let mut str_bytes = item.description.as_bytes().to_vec();
            while str_bytes.len() > 99 {
                str_bytes.pop();
            }
            while str_bytes.len() < 100 {
                str_bytes.push(0);
            }
            buf.write_all(&str_bytes).unwrap()
        }
        buf
    }
    #[derive(Debug)]
    pub struct Candidate {
        pub id: [u8; 4],
        pub description: String,
    }

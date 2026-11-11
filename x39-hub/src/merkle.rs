//! Pruebas de inclusión del HUB con SHA-256 y duplicación del último nodo.
use crate::ErrorHub;
use sha2::{Digest, Sha256};

/// La raíz y el total deben proceder de la misma fuente de confianza y de la misma
/// versión del registro. Al duplicar el último nodo, [A, B, C] y [A, B, C, C]
/// tienen la misma raíz. Quien presenta la prueba no puede escoger el total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnclaRaizHub {
    pub raiz: [u8; 32],
    pub total: u64,
}

/// La posición indica el lado del hermano según el HUB: "L" o "R".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HermanoMerkle {
    pub hash: [u8; 32],
    pub posicion: String,
}

fn nodo(izquierda: &[u8; 32], derecha: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(izquierda);
    hash.update(derecha);
    hash.finalize().into()
}

fn nivel_superior(nivel: &[[u8; 32]]) -> Vec<[u8; 32]> {
    nivel.chunks(2).map(|par| nodo(&par[0], par.get(1).unwrap_or(&par[0]))).collect()
}

/// Cada hoja contiene los 32 bytes crudos del campo sha256.
/// Para una sola hoja se toma la propia hoja como raíz. Este supuesto
/// no se ha contrastado con el HUB, cuya referencia contiene 14 entradas.
pub fn raiz_merkle(hojas: &[[u8; 32]]) -> Result<AnclaRaizHub, ErrorHub> {
    if hojas.is_empty() {
        return Err(ErrorHub::InclusionMerkle);
    }
    let total = u64::try_from(hojas.len()).map_err(|_| ErrorHub::InclusionMerkle)?;
    let mut nivel = hojas.to_vec();
    while nivel.len() > 1 {
        nivel = nivel_superior(&nivel);
    }
    Ok(AnclaRaizHub { raiz: nivel[0], total })
}

/// Construye el camino de la hoja a la raíz. El índice del HUB comienza en 1.
pub fn construir_prueba(hojas: &[[u8; 32]], indice: u64) -> Result<Vec<HermanoMerkle>, ErrorHub> {
    let mut pos = usize::try_from(indice).map_err(|_| ErrorHub::InclusionMerkle)?;
    if pos == 0 || pos > hojas.len() {
        return Err(ErrorHub::InclusionMerkle);
    }
    pos -= 1;
    let mut nivel = hojas.to_vec();
    let mut hermanos = Vec::new();
    while nivel.len() > 1 {
        let (hash, lado) = if pos % 2 == 0 {
            (*nivel.get(pos + 1).unwrap_or(&nivel[pos]), "R")
        } else {
            (nivel[pos - 1], "L")
        };
        hermanos.push(HermanoMerkle { hash, posicion: lado.into() });
        nivel = nivel_superior(&nivel);
        pos /= 2;
    }
    Ok(hermanos)
}

/// Verifica un índice en base 1 contra el ancla de confianza del llamante.
pub fn verificar_inclusion(
    ancla: &AnclaRaizHub,
    hoja: &[u8; 32],
    indice: u64,
    hermanos: &[HermanoMerkle],
) -> Result<(), ErrorHub> {
    if indice == 0 || indice > ancla.total {
        return Err(ErrorHub::InclusionMerkle);
    }
    let mut pos = indice - 1;
    let mut anchura = ancla.total;
    let mut actual = *hoja;
    let mut camino = hermanos.iter();
    while anchura > 1 {
        let hermano = camino.next().ok_or(ErrorHub::InclusionMerkle)?;
        actual = if pos % 2 == 0 {
            if hermano.posicion != "R" || (pos == anchura - 1 && hermano.hash != actual) {
                return Err(ErrorHub::InclusionMerkle);
            }
            nodo(&actual, &hermano.hash)
        } else {
            if hermano.posicion != "L" {
                return Err(ErrorHub::InclusionMerkle);
            }
            nodo(&hermano.hash, &actual)
        };
        pos /= 2;
        anchura = anchura.div_ceil(2);
    }
    if camino.next().is_some() || actual != ancla.raiz {
        return Err(ErrorHub::InclusionMerkle);
    }
    Ok(())
}

/// Comprueba también el campo algorithm cuando se recibe la prueba del HUB.
pub fn verificar_inclusion_hub(
    algoritmo: &str,
    ancla: &AnclaRaizHub,
    hoja: &[u8; 32],
    indice: u64,
    hermanos: &[HermanoMerkle],
) -> Result<(), ErrorHub> {
    if algoritmo != "sha256-binary-duplicate-last" {
        return Err(ErrorHub::InclusionMerkle);
    }
    verificar_inclusion(ancla, hoja, indice, hermanos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::de_hex_32;

    const HOJAS: [&str; 14] = [
        "d6171869351518663b4bb27852ea4ea5e3263047da6eb329650e3c2c632f0c01",
        "93cb815424aa05b294bf7a195b727ee6a9d27e56eac33762baf05d93dbdc4739",
        "6a82c54c2e679c6ebc70bdc58120faa5e241eee06eaa74d9ae4567d16f58efc2",
        "e9466de4e0d1c10b2b6b9e6023166c62d46798cab21372db682ff215cd4eb93f",
        "be87a6a34152c4dab9a512c8886155ff8eaf43d15e50bc41a7f7756b708d65db",
        "40945443f3bc5fde861b3056199def8bf971a368382029cc75b83f079ec48b68",
        "54c2e2c13e48bf6c505e4466b33d7c9cc19e5d4beaec1c87115340fdc2aff668",
        "4ee2bbb48c12b3114661849a39db4382e1736d63c0f78182cd68a8b6e46b6237",
        "98f55f17954b7e8ae7fa3842b869f85e65621b1684c11804c8518d4c2f1bca19",
        "02863d63d3f8b6d976ba1d98214e42e753de27fd72680892d7e8ce5d9f83555a",
        "8b8888733efcc6351a6e9b30fdd58a98418f57ce08f4547f88605941a3a52ba6",
        "6ca522ba094ed26ad6c5d8604a1bbb93daa830639dea55acfd5e7e8b9c7bf986",
        "9fa95af0f379caf183c361d86819666b9f5805b211ffaf23d93a06a08216d043",
        "e39fc1f8fe0d242fc9f116950089ddac17641a16a86973561500ba1ac5f0ee72",
    ];

    const RAIZ: &str = "1bcd7f7345a440d29ee844a79c0242b1346eeca235c91faa1c7f27140488f7db";

    const PRUEBA_14: [(&str, &str); 4] = [
        ("9fa95af0f379caf183c361d86819666b9f5805b211ffaf23d93a06a08216d043", "L"),
        ("c91c2645d8796ecb8458ffc5a35e712bd75070ef290a65406ebcf8ee7aad8425", "R"),
        ("69c3c01b93b4cc0ccee73aaed206374676f8764aa5b10184496502cfd72cfc15", "L"),
        ("18c03c3cd297317ef6a483b1ccb668a7bb88f62a239110d92282234d03eb3491", "L"),
    ];

    fn hojas_reales() -> [[u8; 32]; 14] {
        HOJAS.map(|texto| de_hex_32(texto).unwrap())
    }

    fn ancla_real() -> AnclaRaizHub {
        AnclaRaizHub { raiz: de_hex_32(RAIZ).unwrap(), total: 14 }
    }

    fn prueba_real() -> Vec<HermanoMerkle> {
        PRUEBA_14
            .iter()
            .map(|&(hash, lado)| HermanoMerkle {
                hash: de_hex_32(hash).unwrap(),
                posicion: lado.into(),
            })
            .collect()
    }

    #[test]
    fn las_catorce_hojas_dan_el_ancla_real() {
        assert_eq!(raiz_merkle(&hojas_reales()), Ok(ancla_real()));
    }

    #[test]
    fn la_prueba_real_de_la_entrada_catorce_verifica() {
        let hojas = hojas_reales();
        let prueba = prueba_real();
        assert_eq!(prueba[1].hash, nodo(&hojas[12], &hojas[13]));
        assert_eq!(
            verificar_inclusion_hub(
                "sha256-binary-duplicate-last",
                &ancla_real(),
                &hojas[13],
                14,
                &prueba
            ),
            Ok(())
        );
        for texto in ["", "SHA256-binary-duplicate-last", "sha256-binary-duplicate-last "] {
            assert_eq!(
                verificar_inclusion_hub(texto, &ancla_real(), &hojas[13], 14, &prueba),
                Err(ErrorHub::InclusionMerkle)
            );
        }
    }

    #[test]
    fn construir_la_prueba_catorce_reproduce_los_cuatro_hermanos() {
        assert_eq!(construir_prueba(&hojas_reales(), 14), Ok(prueba_real()));
    }

    #[test]
    fn verifican_las_catorce_pruebas_construidas() {
        let hojas = hojas_reales();
        for (i, hoja) in hojas.iter().enumerate() {
            let indice = i as u64 + 1;
            let prueba = construir_prueba(&hojas, indice).unwrap();
            assert_eq!(verificar_inclusion(&ancla_real(), hoja, indice, &prueba), Ok(()));
        }
    }

    #[test]
    fn el_relleno_no_crea_entradas_quince_y_dieciseis() {
        let hojas = hojas_reales();
        for (original, falso) in [(13_u64, 15_u64), (14, 16)] {
            let hoja = &hojas[original as usize - 1];
            let prueba = construir_prueba(&hojas, original).unwrap();
            assert_eq!(
                verificar_inclusion(&ancla_real(), hoja, falso, &prueba),
                Err(ErrorHub::InclusionMerkle)
            );
        }
    }

    #[test]
    fn se_rechaza_un_nodo_interno_presentado_como_hoja() {
        let hojas = hojas_reales();
        let padre = nodo(&hojas[12], &hojas[13]);
        let prueba = prueba_real();
        assert_eq!(
            verificar_inclusion(&ancla_real(), &padre, 7, &prueba[1..]),
            Err(ErrorHub::InclusionMerkle)
        );
    }

    #[test]
    fn se_rechazan_cambios_de_longitud_datos_indice_y_posicion() {
        let hoja = hojas_reales()[13];
        let ancla = ancla_real();
        let prueba = prueba_real();
        let rechazo = Err(ErrorHub::InclusionMerkle);

        assert_eq!(verificar_inclusion(&ancla, &hoja, 14, &prueba[..3]), rechazo);
        let mut larga = prueba.clone();
        larga.push(prueba[0].clone());
        assert_eq!(verificar_inclusion(&ancla, &hoja, 14, &larga), rechazo);

        let mut alterada = prueba.clone();
        alterada[2].hash[0] ^= 1;
        assert_eq!(verificar_inclusion(&ancla, &hoja, 14, &alterada), rechazo);
        let mut otra_hoja = hoja;
        otra_hoja[0] ^= 1;
        assert_eq!(verificar_inclusion(&ancla, &otra_hoja, 14, &prueba), rechazo);
        assert_eq!(verificar_inclusion(&ancla, &hoja, 13, &prueba), rechazo);

        // El segundo hermano es idéntico al nodo. Intercambiarlos conserva el hash.
        for lado in ["L", "r", "R ", "", "X"] {
            let mut invertida = prueba.clone();
            invertida[1].posicion = lado.into();
            assert_eq!(verificar_inclusion(&ancla, &hoja, 14, &invertida), rechazo);
        }
    }

    #[test]
    fn el_ultimo_nodo_impar_exige_una_copia_exacta() {
        let hojas = [[1; 32], [2; 32], [3; 32], [4; 32]];
        let cuatro = raiz_merkle(&hojas).unwrap();
        let prueba = construir_prueba(&hojas, 3).unwrap();
        assert_eq!(verificar_inclusion(&cuatro, &hojas[2], 3, &prueba), Ok(()));

        // Con total 3, el cuarto valor ocuparía el lugar del duplicado obligatorio.
        let tres = AnclaRaizHub { total: 3, ..cuatro };
        assert_eq!(
            verificar_inclusion(&tres, &hojas[2], 3, &prueba),
            Err(ErrorHub::InclusionMerkle)
        );
    }

    #[test]
    fn arbol_vacio_indices_invalidos_y_hoja_unica() {
        let hoja = [11; 32];
        let vacio = AnclaRaizHub { raiz: hoja, total: 0 };
        assert_eq!(raiz_merkle(&[]), Err(ErrorHub::InclusionMerkle));
        assert_eq!(construir_prueba(&[], 1), Err(ErrorHub::InclusionMerkle));
        assert_eq!(verificar_inclusion(&vacio, &hoja, 1, &[]), Err(ErrorHub::InclusionMerkle));

        let una = AnclaRaizHub { raiz: hoja, total: 1 };
        assert_eq!(raiz_merkle(&[hoja]), Ok(una));
        assert_eq!(construir_prueba(&[hoja], 1), Ok(vec![]));
        assert_eq!(verificar_inclusion(&una, &hoja, 1, &[]), Ok(()));
        for indice in [0, 2] {
            assert_eq!(construir_prueba(&[hoja], indice), Err(ErrorHub::InclusionMerkle));
            assert_eq!(
                verificar_inclusion(&una, &hoja, indice, &[]),
                Err(ErrorHub::InclusionMerkle)
            );
        }
    }

    #[test]
    fn todas_las_posiciones_de_uno_a_treinta_y_tres() {
        let hojas: Vec<[u8; 32]> = (1_u8..=33).map(|i| [i; 32]).collect();
        for total in 1..=hojas.len() {
            let tramo = &hojas[..total];
            let ancla = raiz_merkle(tramo).unwrap();
            assert_eq!(ancla.total, total as u64);
            for (i, hoja) in tramo.iter().enumerate() {
                let indice = i as u64 + 1;
                let prueba = construir_prueba(tramo, indice).unwrap();
                assert_eq!(
                    verificar_inclusion(&ancla, hoja, indice, &prueba),
                    Ok(()),
                    "total {total}, índice {indice}"
                );
            }
        }
    }
}
